import "pe"
rule _RCryptor_v16b__v16c__Vaska_
{
	meta:
		description = "RCryptor v1.6b / v1.6c --> Vaska"
	strings:
		$0 = {8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68}
		$1 = {8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}