import "pe"
rule _DCrypt_Private_09b__drmist_
{
	meta:
		description = "DCrypt Private 0.9b -> drmist"
	strings:
		$0 = {B9 ?? ?? ?? 00 E8 00 00 00 00 58 68 ?? ?? ?? 00 83 E8 0B 0F 18 00 D0 00 48 E2 FB C3}
	condition:
		$0 at pe.entry_point
}