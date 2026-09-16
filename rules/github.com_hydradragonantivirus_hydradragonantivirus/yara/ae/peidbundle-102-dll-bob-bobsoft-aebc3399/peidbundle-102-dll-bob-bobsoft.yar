import "pe"
rule _PEiDBundle_102_DLL__BoB__BobSoft_
{
	meta:
		description = "PEiD-Bundle 1.02 DLL -> BoB / BobSoft"
	strings:
		$0 = {83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00}
	condition:
		$0 at pe.entry_point
}