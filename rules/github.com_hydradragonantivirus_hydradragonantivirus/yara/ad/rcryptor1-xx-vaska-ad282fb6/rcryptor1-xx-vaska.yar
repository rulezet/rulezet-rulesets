rule RCryptor1_xx__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.xx -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 }
	condition:
		$a0
}