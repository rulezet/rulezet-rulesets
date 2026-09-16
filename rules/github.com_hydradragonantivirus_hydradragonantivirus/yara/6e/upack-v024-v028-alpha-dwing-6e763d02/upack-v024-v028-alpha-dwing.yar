import "pe"
rule _Upack_v024__v028_Alpha__Dwing_
{
	meta:
		description = "Upack v0.24 ~ v0.28 Alpha -> Dwing"
	strings:
		$0 = {BE 88 01 40 00 AD ?? ?? 95 AD 91 F3 A5 AD}
	condition:
		$0 at pe.entry_point
}