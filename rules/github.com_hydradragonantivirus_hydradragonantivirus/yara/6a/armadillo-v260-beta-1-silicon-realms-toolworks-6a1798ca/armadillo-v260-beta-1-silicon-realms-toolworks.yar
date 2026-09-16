import "pe"
rule _Armadillo_v260_Beta_1__Silicon_Realms_Toolworks_
{
	meta:
		description = "Armadillo v2.60 Beta 1 -> Silicon Realms Toolworks"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 50 ?? ?? ?? ?? 68 74 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 58 33 D2 8A D4 89}
	condition:
		$0 at pe.entry_point
}