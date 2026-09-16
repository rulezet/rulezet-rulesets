import "pe"
rule _Virtual_Image_Maker_Graphics_file_
{
	meta:
		description = "Virtual Image Maker Graphics file"
	strings:
		$0 = {53 4F 4D 56}
	condition:
		$0 at pe.entry_point
}