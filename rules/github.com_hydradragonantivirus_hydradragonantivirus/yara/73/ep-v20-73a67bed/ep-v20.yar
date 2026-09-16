import "pe"
rule _EP_v20_
{
	meta:
		description = "EP v2.0"
	strings:
		$0 = {60 BE ?? B0 42 ?? 8D BE ?? 60 FD FF C7 87 B0 E4 02 ?? 31 3C 4B DF 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB ?? ?? ??}
	condition:
		$0 at pe.entry_point
}