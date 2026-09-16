import "pe"
rule _ExeLock_100_
{
	meta:
		description = "ExeLock 1.00"
	strings:
		$0 = {06 8C C8 8E C0 BE 17 00 26 8A 04 34 00 26 88 04 46 81 FE 0C 02 75 F1}
	condition:
		$0 at pe.entry_point
}