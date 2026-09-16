import "pe"
rule _PassEXE_20_
{
	meta:
		description = "PassEXE 2.0"
	strings:
		$0 = {06 1E 0E 0E 07 1F 00 00 00 B9 53 01 87}
	condition:
		$0 at pe.entry_point
}