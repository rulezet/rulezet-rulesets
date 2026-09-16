import "pe"
rule _BAFF_BMPs_graphics_library_
{
	meta:
		description = "BAFF (BMP's) graphics library"
	strings:
		$0 = {42 41 46 46 01 00 00 00}
	condition:
		$0 at pe.entry_point
}