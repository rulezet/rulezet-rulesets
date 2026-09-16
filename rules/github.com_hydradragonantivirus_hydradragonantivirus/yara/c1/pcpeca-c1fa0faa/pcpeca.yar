import "pe"
rule pcpeca
{
	meta:
		author = "PEiD"
		description = "PC PE Encryptor alpha preview -> The +Q, Plushmm & Mr. Nop"
		group = "136"
		function = "0"
	strings:
		$a0 = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 8B CD 81 ED 33 30 40 ?? 2B 8D EE 32 40 ?? 83 E9 0B 89 8D F2 32 40 ?? 80 BD D1 32 40 ?? 01 0F 84 }
	condition:
		$a0 at pe.entry_point
}