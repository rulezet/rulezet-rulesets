import "pe"
rule _tElock_v071b2_
{
	meta:
		description = "tElock v0.71b2"
	strings:
		$0 = {60 E8 48 11 ?? ?? C3}
	condition:
		$0 at pe.entry_point
}