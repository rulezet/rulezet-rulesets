import "pe"
rule _setupexe_Section44rsrc_
{
	meta:
		description = "setup.exe Section(4/4,.rsrc)"
	strings:
		$0 = {00 00 00 00 00 00 00 00 04 00 00 00 00 00 04 00 03 00 00 00 30 00 00}
	condition:
		$0 at pe.entry_point
}