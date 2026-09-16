import "pe"
rule _Upack_Patch_or_any_Version__Sign_by_hot_UNP_
{
	meta:
		description = "Upack_Patch or any Version -> Sign by hot_UNP"
	strings:
		$0 = {60 E8 09 00 00 00 ?? ?? ?? 00 E9 06 02}
	condition:
		$0 at pe.entry_point
}