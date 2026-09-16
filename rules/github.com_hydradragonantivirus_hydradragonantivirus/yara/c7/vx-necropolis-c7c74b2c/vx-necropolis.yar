import "pe"
rule _Vx_Necropolis_
{
	meta:
		description = "Vx: Necropolis"
	strings:
		$0 = {50 FC AD 33 C2 AB 8B D0 E2 F8}
	condition:
		$0 at pe.entry_point
}