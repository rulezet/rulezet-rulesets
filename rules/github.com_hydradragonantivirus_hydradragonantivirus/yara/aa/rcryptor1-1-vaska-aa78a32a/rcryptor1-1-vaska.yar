import "pe"
rule RCryptor1_1__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.1 -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 8B 04 24 83 E8 4F 68 ?? ?? ?? ?? FF D0 }
	condition:
		$a0 at pe.entry_point
}