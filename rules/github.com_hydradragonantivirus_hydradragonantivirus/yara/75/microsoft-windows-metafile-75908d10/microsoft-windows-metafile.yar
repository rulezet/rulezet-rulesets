import "pe"
rule _Microsoft_Windows_Metafile_
{
	meta:
		description = "Microsoft Windows Metafile"
	strings:
		$0 = {D7 CD C6 9A}
	condition:
		$0 at pe.entry_point
}