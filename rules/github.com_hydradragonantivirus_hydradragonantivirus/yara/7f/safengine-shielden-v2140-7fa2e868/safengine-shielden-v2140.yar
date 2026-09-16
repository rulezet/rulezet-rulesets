import "pe"
rule _Safengine_Shielden_v2140_
{
	meta:
		description = "Safengine Shielden v2.1.4.0"
	strings:
		$0 = {E8 ?? ?? ?? ?? 53 61 66 65 6E 67 69 6E 65 20 53 68 69 65 6C 64 65 6E 20 76 32 2E 31 2E 34 2E 30 00}
	condition:
		$0 at pe.entry_point
}