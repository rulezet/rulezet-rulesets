import "pe"
rule _EXE32Pack_v139_
{
	meta:
		description = "EXE32Pack v1.39"
	strings:
		$0 = {3B 74 02 81 83 55 3B 74 02 81 53 3B 74 01 02 81 E8 3B 74 01 5D 8B D5 81}
	condition:
		$0 at pe.entry_point
}