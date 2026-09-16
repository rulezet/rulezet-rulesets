import "pe"
rule _nPack_v11_150200_Beta__NEOx_
{
	meta:
		description = "nPack v1.1 150-200 Beta -> NEOx"
	strings:
		$0 = {83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? 00 E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00}
	condition:
		$0 at pe.entry_point
}