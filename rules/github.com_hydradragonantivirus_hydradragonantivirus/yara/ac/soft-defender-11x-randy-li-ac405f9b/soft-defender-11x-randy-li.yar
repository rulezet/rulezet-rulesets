import "pe"
rule _Soft_Defender_11x__Randy_Li_
{
	meta:
		description = "Soft Defender 1.1x -> Randy Li"
	strings:
		$0 = {74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44}
	condition:
		$0 at pe.entry_point
}