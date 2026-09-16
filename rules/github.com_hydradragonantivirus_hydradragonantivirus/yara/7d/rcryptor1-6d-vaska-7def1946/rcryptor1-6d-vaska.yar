rule RCryptor1_6d__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.6d -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 }
	condition:
		$a0
}