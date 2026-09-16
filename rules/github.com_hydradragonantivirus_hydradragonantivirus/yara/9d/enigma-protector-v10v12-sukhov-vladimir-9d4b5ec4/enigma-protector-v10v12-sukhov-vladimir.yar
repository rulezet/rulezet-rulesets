import "pe"
rule _ENIGMA_Protector_V10V12_Sukhov_Vladimir_
{
	meta:
		description = "ENIGMA Protector V1.0-V1.2-> Sukhov Vladimir"
	strings:
		$0 = {60 E8 00 00 00 00 5D 83 ?? ?? 81}
		$1 = {60 E8 00 00 00 00 5D 83 ?? ?? 81}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}