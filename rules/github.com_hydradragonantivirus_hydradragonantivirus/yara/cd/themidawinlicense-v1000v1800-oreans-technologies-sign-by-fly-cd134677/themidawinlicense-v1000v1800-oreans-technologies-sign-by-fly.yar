import "pe"
rule _ThemidaWinLicense_V1000V1800__Oreans_Technologies__Sign_by_fly_
{
	meta:
		description = "Themida/WinLicense V1.0.0.0-V1.8.0.0 -> Oreans Technologies ! Sign by fly"
	strings:
		$0 = {B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? E8 00 00 00 00}
	condition:
		$0 at pe.entry_point
}