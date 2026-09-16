import "pe"
rule _BDC_HelpSystem_Help_file_
{
	meta:
		description = "BDC HelpSystem Help file"
	strings:
		$0 = {42 44 43 20 48 65 6C 70 53 79 73 74 65 6D}
	condition:
		$0 at pe.entry_point
}