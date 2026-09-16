import "pe"
rule _Adobe_PDF_Portable_document_Version_v3v4_
{
	meta:
		description = "Adobe PDF (Portable document) Version %v3.%v4"
	strings:
		$0 = {25 50 44 46 2D ?? 2E}
	condition:
		$0 at pe.entry_point
}