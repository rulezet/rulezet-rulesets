import "pe"
rule _Upack_v021Beta__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.21Beta -> Sign by hot_UNP"
	strings:
		$0 = {BE 88 01 ?? ?? AD 8B F8 ?? ?? ?? ?? 33}
	condition:
		$0 at pe.entry_point
}