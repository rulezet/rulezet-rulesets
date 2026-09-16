import "pe"
rule _NFO_10_
{
	meta:
		description = "NFO 1.0"
	strings:
		$0 = {60 9C 8D 50 12 2B C9 B1 1E 8A 02 34 00 88 02 42 E2 F7}
	condition:
		$0 at pe.entry_point
}