import "pe"
rule _Windows_Write_file_
{
	meta:
		description = "Windows Write file"
	strings:
		$0 = {BE 00 00 00 AB 00 00 00}
	condition:
		$0 at pe.entry_point
}