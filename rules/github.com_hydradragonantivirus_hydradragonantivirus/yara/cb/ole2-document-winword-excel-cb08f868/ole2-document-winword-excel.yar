import "pe"
rule _OLE2_Document_WinWord_Excel__
{
	meta:
		description = "OLE2 Document (WinWord, Excel ...)"
	strings:
		$0 = {D0 CF 11 E0 A1 B1 1A E1}
	condition:
		$0 at pe.entry_point
}