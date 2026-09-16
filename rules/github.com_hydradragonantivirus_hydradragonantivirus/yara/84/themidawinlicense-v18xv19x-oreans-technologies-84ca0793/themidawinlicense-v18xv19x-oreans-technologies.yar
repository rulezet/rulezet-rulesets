import "pe"
rule _ThemidaWinLicense_V18XV19X__Oreans_Technologies_
{
	meta:
		description = "Themida/WinLicense V1.8.X-V1.9.X -> Oreans Technologies"
	strings:
		$0 = {B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D ?? ?? ?? ?? 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3}
	condition:
		$0 at pe.entry_point
}