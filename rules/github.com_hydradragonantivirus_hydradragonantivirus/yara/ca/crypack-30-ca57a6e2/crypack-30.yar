import "pe"
rule _CRYPACK_30_
{
	meta:
		description = "CRYPACK 3.0"
	strings:
		$0 = {06 1E 8C D8 05 10 00 8E D8 33 DB 0E 07 33 FF BE A1 01 8A 07 26 8A 25 32 C4 88 07 47 3B FE 74 08 43 83 FB 10 74 06 EB EA 33 FF EB F4 33 DB 8C D8 40 8E D8 8C C9 3B C1 74 02 EB D7 1F 07 06 1E 2E A1 05 00 8C C3 83 C3 10 03 C3 2E A3 05 00 FA 33}
	condition:
		$0 at pe.entry_point
}