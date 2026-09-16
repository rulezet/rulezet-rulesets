import "pe"
rule execryptor13045
{
	meta:
		author = "PEiD"
		description = "EXECryptor 1.3.0.45 -> SoftLab MIL-TEC Ltd."
		group = "120"
		function = "0"
	strings:
		$a0 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 }
	condition:
		$a0 at pe.entry_point
}