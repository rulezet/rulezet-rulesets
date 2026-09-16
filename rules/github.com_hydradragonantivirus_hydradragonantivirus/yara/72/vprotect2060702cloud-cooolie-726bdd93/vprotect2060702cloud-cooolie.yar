import "pe"
rule _VProtect2060702Cloud__CoooLie_
{
	meta:
		description = "VProtect.2.0.6.0702.Cloud -> CoooLie"
	strings:
		$0 = {66 8B C9 8D 89 F9 FF FF FF 8A D2 8D 89 07 00 00 00 66 53 8B C9 66 5B 9C 9D 8B 67 28 8D AD FF FF FF FF 66 F7 D1 9C 9D 66 F7 D1 8D AD 01 00 00 00 61 52 5A 9D 66 51 66 87 CD 66 87 CD 66 59 C3}
	condition:
		$0 at pe.entry_point
}