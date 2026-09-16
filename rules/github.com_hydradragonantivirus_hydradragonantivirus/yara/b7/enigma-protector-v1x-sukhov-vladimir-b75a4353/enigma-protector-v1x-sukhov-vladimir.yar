import "pe"
rule _ENIGMA_Protector_V1X_Sukhov_Vladimir_
{
	meta:
		description = "ENIGMA Protector V1.X-> Sukhov Vladimir"
	strings:
		$0 = {45 6E 69 67 6D 61 20 70 72 6F 74 65 63 74 6F 72 20 76 31}
	condition:
		$0 at pe.entry_point
}