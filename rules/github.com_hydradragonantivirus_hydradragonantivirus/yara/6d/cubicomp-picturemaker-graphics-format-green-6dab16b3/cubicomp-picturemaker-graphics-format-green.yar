import "pe"
rule _CubiComp_PictureMaker_graphics_format_green_
{
	meta:
		description = "CubiComp PictureMaker graphics format (green)"
	strings:
		$0 = {26 0C FF 02 00 00 00 00}
	condition:
		$0 at pe.entry_point
}