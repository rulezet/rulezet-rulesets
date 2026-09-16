import "pe"
rule _ENIGMA_Protector_V11_Sukhov_Vladimir_
{
	meta:
		description = "ENIGMA Protector V1.1-> Sukhov Vladimir"
	strings:
		$0 = {60 E8 00 00 00 00 5D 83 ?? ?? 81}
	condition:
		$0 at pe.entry_point
}