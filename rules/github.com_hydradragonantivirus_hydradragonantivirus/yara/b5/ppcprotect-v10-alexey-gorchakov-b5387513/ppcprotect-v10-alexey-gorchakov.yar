import "pe"
rule _PPCPROTECT_V10__Alexey_Gorchakov_
{
	meta:
		description = "PPC-PROTECT V1.0 -> Alexey Gorchakov"
	strings:
		$0 = {FF 5F 2D E9}
	condition:
		$0 at pe.entry_point
}