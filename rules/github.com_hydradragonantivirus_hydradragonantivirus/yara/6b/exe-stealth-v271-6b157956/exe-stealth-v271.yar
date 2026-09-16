import "pe"
rule _EXE_Stealth_v271_
{
	meta:
		description = "EXE Stealth v2.71"
	strings:
		$0 = {EB ?? EB 2F 53 68 61 72 65 77 61 72 65 20 2D}
	condition:
		$0 at pe.entry_point
}