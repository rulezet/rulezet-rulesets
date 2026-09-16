import "pe"
rule _Armadillo_V520Beta1__Silicon_Realms_Toolworks___20080214_
{
	meta:
		description = "Armadillo V5.20.Beta1 -> Silicon Realms Toolworks  * 20080214"
	strings:
		$0 = {E8 8E 3F 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 9E 16 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 F5 14 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 86 14 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75}
	condition:
		$0 at pe.entry_point
}