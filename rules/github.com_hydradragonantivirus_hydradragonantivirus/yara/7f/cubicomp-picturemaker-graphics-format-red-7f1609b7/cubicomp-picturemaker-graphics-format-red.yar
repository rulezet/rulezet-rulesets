import "pe"
rule _CubiComp_PictureMaker_graphics_format_red_
{
	meta:
		description = "CubiComp PictureMaker graphics format (red)"
	strings:
		$0 = {16 0C FF 02 00 00 00 00}
	condition:
		$0 at pe.entry_point
}