import "pe"
rule _Lotus_Word_Pro_document_file_
{
	meta:
		description = "Lotus Word Pro document file"
	strings:
		$0 = {57 6F 72 64 50 72 6F ?? ?? ?? ?? ?? ?? ?? ?? ?? 4C 57 50 37}
	condition:
		$0 at pe.entry_point
}