import "pe"
rule _RCryptor_v1__Vaska_
{
	meta:
		description = "RCryptor v1.?? -> Vaska"
	strings:
		$0 = {90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68}
		$1 = {90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}