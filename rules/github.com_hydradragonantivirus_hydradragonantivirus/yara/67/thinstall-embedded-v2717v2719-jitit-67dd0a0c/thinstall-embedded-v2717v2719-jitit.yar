import "pe"
rule _Thinstall_Embedded_V2717V2719__Jitit_
{
	meta:
		description = "Thinstall Embedded V2.717-V2.719 -> Jitit"
	strings:
		$0 = {9C 60 E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 C1 FE FF FF E9 97 FF FF FF CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D}
	condition:
		$0 at pe.entry_point
}