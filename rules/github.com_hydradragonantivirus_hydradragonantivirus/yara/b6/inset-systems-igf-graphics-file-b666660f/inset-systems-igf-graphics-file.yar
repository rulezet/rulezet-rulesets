import "pe"
rule _Inset_Systems_IGF_graphics_file_
{
	meta:
		description = "Inset Systems IGF graphics file"
	strings:
		$0 = {01 80 04 00 01 00 58 00}
	condition:
		$0 at pe.entry_point
}