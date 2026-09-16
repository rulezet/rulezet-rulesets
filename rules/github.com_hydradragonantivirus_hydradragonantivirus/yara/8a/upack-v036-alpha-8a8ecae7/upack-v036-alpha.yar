import "pe"
rule _Upack_v036_alpha_
{
	meta:
		description = "Upack v0.36 alpha"
	strings:
		$0 = {AB E2 E5 5D 59 8B 76 68 51 59 46 AD 85 C0}
	condition:
		$0 at pe.entry_point
}