import "pe"
rule _PEncrypt_v31__JunkCode_
{
	meta:
		description = "PEncrypt v3.1 -> JunkCode"
	strings:
		$0 = {E9 ?? ?? ?? 00 F0 0F C6}
	condition:
		$0 at pe.entry_point
}