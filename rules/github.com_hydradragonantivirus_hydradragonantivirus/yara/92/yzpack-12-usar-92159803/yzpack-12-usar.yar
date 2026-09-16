import "pe"
rule _YZPack_12__UsAr_
{
	meta:
		description = "YZPack 1.2 --> UsAr"
	strings:
		$0 = {4D 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9}
	condition:
		$0 at pe.entry_point
}