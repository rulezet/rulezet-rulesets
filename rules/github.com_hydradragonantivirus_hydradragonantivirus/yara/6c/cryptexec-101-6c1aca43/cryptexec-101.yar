import "pe"
rule _CrypteXeC_101_
{
	meta:
		description = "CrypteXeC 1.01"
	strings:
		$0 = {FD 25 29 70 E8 08 01 AE 12 3F E8 27 00 FD E9 12 00 3E 26 F6 D9 26 1C 99 2E F5 FD C3 84 19 22 C5 04 D3 AC E8 33 01 B4 0B CD 21 F5 3E 84 17 F6 DB AC E9 1C 00 F6 D9 35 AC 5E 90 E8 D4 FF F8 3D 19 F0 E8 CD FF 3C 28 E8 C8 FF FB 2C 49 C3 02 09 D7}
	condition:
		$0 at pe.entry_point
}