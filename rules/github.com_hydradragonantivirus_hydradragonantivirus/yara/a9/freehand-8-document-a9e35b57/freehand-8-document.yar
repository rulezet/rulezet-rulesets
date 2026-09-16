import "pe"
rule _FreeHand_8_document_
{
	meta:
		description = "FreeHand 8 document"
	strings:
		$0 = {41 47 44 33}
	condition:
		$0 at pe.entry_point
}