import "pe"
rule _tElock_v042_
{
	meta:
		description = "tElock v0.42"
	strings:
		$0 = {C1 EE ?? 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 ?? ?? ?? ?? 5E 83 C6 5E 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB}
	condition:
		$0 at pe.entry_point
}