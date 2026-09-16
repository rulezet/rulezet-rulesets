import "pe"
rule _Microsoft_Windows_Shortcut_file_
{
	meta:
		description = "Microsoft Windows Shortcut file"
	strings:
		$0 = {4C 00 00 00 01 14 02 00 00 00}
	condition:
		$0 at pe.entry_point
}