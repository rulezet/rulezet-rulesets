import "pe"
rule _CubiComp_PictureMaker_graphics_format_blue_
{
	meta:
		description = "CubiComp PictureMaker graphics format (blue)"
	strings:
		$0 = {36 0C FF 02 00 00 00 00}
	condition:
		$0 at pe.entry_point
}