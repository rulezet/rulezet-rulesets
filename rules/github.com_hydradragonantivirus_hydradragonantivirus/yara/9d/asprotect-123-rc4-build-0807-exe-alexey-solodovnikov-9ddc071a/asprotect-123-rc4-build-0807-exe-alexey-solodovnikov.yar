import "pe"
rule _ASProtect_123_RC4_build_0807_exe__Alexey_Solodovnikov_
{
	meta:
		description = "ASProtect 1.23 RC4 build 08.07 (exe) -> Alexey Solodovnikov"
	strings:
		$0 = {90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}