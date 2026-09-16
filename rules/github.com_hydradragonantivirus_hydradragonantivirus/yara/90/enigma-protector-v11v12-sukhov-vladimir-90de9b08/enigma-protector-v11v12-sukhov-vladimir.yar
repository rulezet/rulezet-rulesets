import "pe"
rule _ENIGMA_Protector_V11V12__Sukhov_Vladimir_
{
	meta:
		description = "ENIGMA Protector V1.1-V1.2 -> Sukhov Vladimir"
	strings:
		$0 = {60 E8 00 00 00 00 5D 83 ED 06 81}
	condition:
		$0 at pe.entry_point
}