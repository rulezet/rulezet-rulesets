import "pe"
rule _Portable_BitMap_PBM_Graphics_format_
{
	meta:
		description = "Portable BitMap (PBM) Graphics format"
	strings:
		$0 = {50 36 0A}
	condition:
		$0 at pe.entry_point
}