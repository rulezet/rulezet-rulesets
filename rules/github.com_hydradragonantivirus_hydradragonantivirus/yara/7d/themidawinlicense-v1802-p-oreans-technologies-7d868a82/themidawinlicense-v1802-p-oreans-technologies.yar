import "pe"
rule _ThemidaWinLicense_V1802_p__Oreans_Technologies_
{
	meta:
		description = "Themida/WinLicense V1.8.0.2 + -> Oreans Technologies"
	strings:
		$0 = {B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00}
	condition:
		$0 at pe.entry_point
}