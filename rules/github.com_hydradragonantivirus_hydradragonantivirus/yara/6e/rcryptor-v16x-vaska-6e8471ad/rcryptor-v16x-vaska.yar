import "pe"
rule _RCryptor_v16x__Vaska_
{
	meta:
		description = "RCryptor v1.6x --> Vaska"
	strings:
		$0 = {60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? C3}
	condition:
		$0 at pe.entry_point
}