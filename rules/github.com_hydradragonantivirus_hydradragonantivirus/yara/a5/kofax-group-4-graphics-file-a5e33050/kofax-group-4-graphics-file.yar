import "pe"
rule _Kofax_Group_4_graphics_file_
{
	meta:
		description = "Kofax Group 4 graphics file"
	strings:
		$0 = {2E 4B 46 68 80 00 01 00}
	condition:
		$0 at pe.entry_point
}