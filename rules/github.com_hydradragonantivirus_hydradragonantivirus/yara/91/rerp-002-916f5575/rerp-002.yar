import "pe"
rule _RERP_002_
{
	meta:
		description = "RERP 0.02"
	strings:
		$0 = {FC 1E 06 8C C3 83 C3 10 0E 1F BE 38 00 B9 FF FF AD 3B C1 75 0A AD 3B C1 74 0C 03 C3 8E C0 AD 8B F8 26 01 1D EB EA 07 1F 2E 03 1E 36 00 53 2E FF 36 34 00 CB 00 00 00 00 FF FF}
	condition:
		$0 at pe.entry_point
}