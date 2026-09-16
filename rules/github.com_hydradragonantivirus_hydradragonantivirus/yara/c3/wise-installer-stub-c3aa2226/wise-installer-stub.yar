import "pe"
rule _Wise_Installer_Stub_
{
	meta:
		description = "Wise Installer Stub"
	strings:
		$0 = {55 8B EC 81 EC 78 05 ?? ?? 53 56 BE 04 01 ?? ?? 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 ?? 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 ?? 8B 3D 2C 20 40 ?? 53 53}
		$1 = {55 8B EC 81 EC 40 0F ?? ?? 53 56 57 6A 04 FF 15 F4 30 40 ?? FF 15 74 30 40 ?? 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}