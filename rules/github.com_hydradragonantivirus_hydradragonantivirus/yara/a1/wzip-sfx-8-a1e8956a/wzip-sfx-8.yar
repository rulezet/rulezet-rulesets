import "pe"
rule wzip_sfx_8
{
	meta:
		author = "PEiD"
		description = "WinZip 32-bit SFX 8.x module"
		group = "190"
		function = "0"
	strings:
		$a0 = { 53 FF 15 ?? ?? ?? ?? B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 }
	condition:
		$a0 at pe.entry_point
}