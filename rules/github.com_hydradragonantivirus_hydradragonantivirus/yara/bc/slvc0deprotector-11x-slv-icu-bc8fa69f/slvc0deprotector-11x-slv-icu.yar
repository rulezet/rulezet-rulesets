import "pe"
rule _SLVc0deProtector_11x__SLV__ICU_
{
	meta:
		description = "SLVc0deProtector 1.1x -> SLV / ICU"
	strings:
		$0 = {E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C ?? ?? 00}
	condition:
		$0 at pe.entry_point
}