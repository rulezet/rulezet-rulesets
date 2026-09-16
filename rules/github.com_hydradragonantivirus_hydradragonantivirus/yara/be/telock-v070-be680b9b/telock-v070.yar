import "pe"
rule _tElock_v070_
{
	meta:
		description = "tElock v0.70"
	strings:
		$0 = {60 E8 ED 10 ?? ?? C3}
	condition:
		$0 at pe.entry_point
}