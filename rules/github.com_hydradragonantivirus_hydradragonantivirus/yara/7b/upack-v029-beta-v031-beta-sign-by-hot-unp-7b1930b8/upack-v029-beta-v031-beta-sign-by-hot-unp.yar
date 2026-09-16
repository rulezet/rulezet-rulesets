rule _Upack_v029_Beta__v031_Beta__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.29 Beta ~ v0.31 Beta -> Sign by hot_UNP"
	strings:
		$0 = {BE 88 01 ?? ?? AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3}
	condition:
		$0
}