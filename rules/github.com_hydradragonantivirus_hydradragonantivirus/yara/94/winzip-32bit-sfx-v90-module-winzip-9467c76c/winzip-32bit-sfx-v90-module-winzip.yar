import "pe"
rule _WinZip_32bit_SFX_v90_module__Winzip_
{
	meta:
		description = "WinZip 32-bit SFX v9.0 module -> Winzip"
	strings:
		$0 = {53 FF 15 ?? ?? ?? 00 B3 22 38 18 74 03 80 C3 FE 40 33 D2 8A 08 3A CA 74 10 3A CB 74 07 40 8A}
	condition:
		$0 at pe.entry_point
}