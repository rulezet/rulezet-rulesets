import "pe"
rule _ExeShield_v37__ExeShield_Team_h_
{
	meta:
		description = "ExeShield v3.7 -> ExeShield Team (h)"
	strings:
		$0 = {B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC E9 FB C8 4F 1B 22 7C B4 C8 0D BD 71 A9 C8 1F 5F B1 29 8F 11 73 8F 00 D1 88 87 A9 3F 4D 00 6C 3C BF C0 80 F7 AD 35 23 EB 84 82 6F 8C B9 0A FC EC E4 82 97 AE 0F 18 D2 47 1B 65 EA 46 A5 FD 3E 9D 75 2A 62 80 60 F9 B0 0D E1 AC 12 0E 9D 24 D5 43 CE 9A D6 18 BF 22 DA 1F 72 76 B0 98 5B C2 64 BC AE D8}
	condition:
		$0 at pe.entry_point
}