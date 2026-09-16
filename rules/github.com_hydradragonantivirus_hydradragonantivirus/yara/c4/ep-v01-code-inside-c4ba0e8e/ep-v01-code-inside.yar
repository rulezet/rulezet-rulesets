import "pe"
rule _EP_v01__CoDe_Inside_
{
	meta:
		description = "EP v0.1 -> CoDe_Inside"
	strings:
		$0 = {50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC AA 86 C4}
	condition:
		$0 at pe.entry_point
}