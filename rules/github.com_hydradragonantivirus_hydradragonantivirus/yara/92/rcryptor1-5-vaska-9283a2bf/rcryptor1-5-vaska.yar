rule RCryptor1_5__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.5 -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F }
	condition:
		$a0
}