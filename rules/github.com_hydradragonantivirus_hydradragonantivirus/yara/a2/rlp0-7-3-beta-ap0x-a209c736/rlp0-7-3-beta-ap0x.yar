import "pe"
rule RLP0_7_3_beta__ap0x
{
	meta:
		author = "PEiD"
		description = "RLP 0.7.3.beta -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 2E 72 6C 70 00 00 00 00 00 50 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 }
	condition:
		$a0 at pe.entry_point
}