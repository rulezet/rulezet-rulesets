import "pe"
rule _Safeguard_10__Simonzh_
{
	meta:
		description = "Safeguard 1.0 -> Simonzh"
	strings:
		$0 = {E8 00 00 00 00 EB 29}
	condition:
		$0 at pe.entry_point
}