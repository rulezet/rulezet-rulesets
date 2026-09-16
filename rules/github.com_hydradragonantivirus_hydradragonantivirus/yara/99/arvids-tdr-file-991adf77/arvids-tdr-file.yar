import "pe"
rule _ARVIDs_TDR_file_
{
	meta:
		description = "ARVID's TDR file"
	strings:
		$0 = {74 00 00 00}
	condition:
		$0 at pe.entry_point
}