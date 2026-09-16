import "pe"
rule _tElock_v071b7_
{
	meta:
		description = "tElock v0.71b7"
	strings:
		$0 = {60 E8 F9 11 ?? ?? C3}
	condition:
		$0 at pe.entry_point
}