import "pe"
rule _Safeguard_103__Simonzh_
{
	meta:
		description = "Safeguard 1.03 -> Simonzh"
	strings:
		$0 = {E8 ?? 00 00 00}
	condition:
		$0 at pe.entry_point
}