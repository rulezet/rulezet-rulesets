import "pe"
rule _Mask_25_
{
	meta:
		description = "Mask 2.5"
	strings:
		$0 = {55 57 CD 03 FC 4D 41 53 4B FD 50 FA 8B C4 F7 DC BC 01 00 94 49 FB D6 51 52 1F 52 56 B4 30 CD 21 C7 06 00 00 0D 0A C7 06 00 00 07 24 BA 00 00 B4 09 EB 00 B9 53 01 56 5D BE 00 00 56 5F B8 15 35 CD 21 06 53 BA 00 00 0E 07 B4 25 CD 21 EB 1B 05}
	condition:
		$0 at pe.entry_point
}