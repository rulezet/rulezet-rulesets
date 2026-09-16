import "pe"
rule _PEnguinCrypt_v10_
{
	meta:
		description = "PEnguinCrypt v1.0"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D B9 80 31 15 41 81}
	condition:
		$0 at pe.entry_point
}