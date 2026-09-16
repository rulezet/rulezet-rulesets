import "pe"
rule _HiJaak_Image_Draw_Graphics_format_
{
	meta:
		description = "HiJaak Image Draw Graphics format"
	strings:
		$0 = {47 53 44 31 02 00 11 00}
	condition:
		$0 at pe.entry_point
}