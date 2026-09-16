import "pe"
rule _EXECryptor_v13045_
{
	meta:
		description = "EXECryptor v1.3.0.45"
	strings:
		$0 = {E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 31 C0 89 41 14 89 41 18 80}
		$1 = {E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}