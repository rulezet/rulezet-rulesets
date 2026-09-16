rule RCryptor1_3b__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.3b -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 61 83 EF 4F 60 68 ?? ?? ?? ?? FF D7 }
	condition:
		$a0
}