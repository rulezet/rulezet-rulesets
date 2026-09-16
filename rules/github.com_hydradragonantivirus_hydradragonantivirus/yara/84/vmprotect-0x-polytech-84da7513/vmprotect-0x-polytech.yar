import "pe"
rule _VMProtect_0x__PolyTech_
{
	meta:
		description = "VMProtect 0.x -> PolyTech"
	strings:
		$0 = {5B 20 56 4D 50 72 6F 74 65 63 74 20}
	condition:
		$0 at pe.entry_point
}