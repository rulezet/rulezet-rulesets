import "pe"
rule _ENIGMA_Protector_V11_CracKed_By_shoooo__fly__Sukhov_Vladimir_
{
	meta:
		description = "ENIGMA Protector V1.1 CracKed By: shoooo & fly -> Sukhov Vladimir"
	strings:
		$0 = {60 E8 00 00 00 00 5D 83 C5 FA 81}
	condition:
		$0 at pe.entry_point
}