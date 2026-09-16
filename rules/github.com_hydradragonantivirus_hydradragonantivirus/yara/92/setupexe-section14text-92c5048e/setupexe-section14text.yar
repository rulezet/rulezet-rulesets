import "pe"
rule _setupexe_Section14text_
{
	meta:
		description = "setup.exe Section(1/4,.text)"
	strings:
		$0 = {55 8B EC B8 7A 31 00 00 83 EC 08 53 56 57 A3 E8 5E 48 00 A3 EC 5E 48}
	condition:
		$0 at pe.entry_point
}