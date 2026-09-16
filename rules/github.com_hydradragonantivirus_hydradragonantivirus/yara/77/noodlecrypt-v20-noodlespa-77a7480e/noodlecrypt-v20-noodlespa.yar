import "pe"
rule _NoodleCrypt_v20__NoodleSpa_
{
	meta:
		description = "NoodleCrypt v2.0 -> NoodleSpa"
	strings:
		$0 = {EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01}
	condition:
		$0 at pe.entry_point
}