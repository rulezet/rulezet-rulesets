import "pe"
rule _JDProtectV20081208demo_DLL____20090119_
{
	meta:
		description = "JDProtect.V20081208.demo DLL -> ��������Ƽ� * 20090119"
	strings:
		$0 = {8B 44 24 08 83 F8 01 75 1F E8 92 FE FF FF E8 3D 01 00 00 8B 44 24 0C 8B 4C 24 04 50 6A 01 51 E8 5C 57 00 00 83 C4 0C C3 85 C0 75 1E 8B 54 24 0C 52 50 8B 44 24 0C 50 E8 44 57 00 00 83 C4 0C E8 7C 46 00 00 B8 01 00 00 00 C3 8B 4C 24 0C 8B 54 24 04 51 50 52 E8 26 57 00 00 83 C4 0C C3 90 90 E8}
	condition:
		$0 at pe.entry_point
}