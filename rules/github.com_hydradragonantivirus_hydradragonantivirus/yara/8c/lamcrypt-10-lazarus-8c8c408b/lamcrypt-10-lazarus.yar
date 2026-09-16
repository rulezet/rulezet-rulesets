import "pe"
rule _LamCrypt_10__LaZaRuS_
{
	meta:
		description = "LamCrypt 1.0 -> LaZaRuS"
	strings:
		$0 = {60 66 9C BB 00 ?? ?? 00 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 B8}
	condition:
		$0 at pe.entry_point
}