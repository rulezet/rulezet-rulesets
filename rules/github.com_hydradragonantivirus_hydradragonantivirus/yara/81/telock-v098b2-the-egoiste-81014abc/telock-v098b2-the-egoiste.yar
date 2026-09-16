import "pe"
rule _tElock_v098b2__tHE_EGOiSTE_
{
	meta:
		description = "tElock v0.98b2 -> tHE EGOiSTE"
	strings:
		$0 = {E9 1B E4 FF FF}
	condition:
		$0 at pe.entry_point
}