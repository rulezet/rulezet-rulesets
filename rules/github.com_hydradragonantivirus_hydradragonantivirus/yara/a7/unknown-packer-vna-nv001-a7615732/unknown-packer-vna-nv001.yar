import "pe"
rule _Unknown_packer_vna_NV001_
{
	meta:
		description = "Unknown_packer vna NV001"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 03 1E 40 00 33 C0 33 DB 33 D2 EB 01 E8 B9 A0 86 01 00 0F 31 33 C9 03 C8 0F 31 2B C1 3D FF 0F 00 00 0F 83 34 06 00 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 83 F8 01}
	condition:
		$0 at pe.entry_point
}