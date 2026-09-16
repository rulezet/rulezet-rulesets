import "pe"
rule _NT_Shell_40_
{
	meta:
		description = "NT Shell 4.0"
	strings:
		$0 = {2E 8C 1E FE 00 8C CA 8E DA 8E C2 FA 8E D2 BC FE 00 FB E8 00 00 EB 01 EA B9 A7 1E 5E 8B FE EB 01 EA 83 C7 65 2B CF EB 01 EA 32 D2 33 ED 33 DB EB 01 CD 8A 05 8A F0 EB 01 EA 2A C2 34 00 EB 01 EA 2C 00 51 EB 01 CD 8B CD EB 01 EA EB 01 EA D2 C8}
	condition:
		$0 at pe.entry_point
}