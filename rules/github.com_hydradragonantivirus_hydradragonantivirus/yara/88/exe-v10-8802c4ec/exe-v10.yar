import "pe"
rule _EXE_v10___
{
	meta:
		description = "Unknown"
	strings:
		$0 = {55 8B EC 6A FF 68 08 4B 40 00 68 36 3A 40 00 64 A1}
	condition:
		$0 at pe.entry_point
}