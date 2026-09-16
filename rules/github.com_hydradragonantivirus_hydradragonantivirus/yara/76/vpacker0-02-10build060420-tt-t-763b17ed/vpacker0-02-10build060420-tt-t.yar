import "pe"
rule VPacker0_02_10build060420__tt_t_
{
	meta:
		author = "PEiD"
		description = "VPacker 0.02.10 build 060420 -> tt.t"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 C4 D4 53 56 57 8B 45 10 83 C0 0C 8B 00 89 45 DC 83 7D DC 00 75 08 E8 AD FF FF FF 89 45 DC E8 B9 FE FF FF 8B 10 03 55 DC 89 55 E4 83 C0 04 8B 10 89 55 FC 83 C0 04 8B 10 89 55 F4 83 C0 04 8B 10 89 55 F8 83 C0 04 8B 10 89 55 F0 83 C0 04 8B 10 89 55 EC 83 C0 04 8B 00 89 45 E8 8B 45 E4 8B 58 04 03 5D E4 8B FB 8B 45 E4 8B 30 4E 85 F6 72 2B 46 C7 45 E0 00 00 00 00 83 7B 04 00 74 14 8B 03 03 C7 8B 53 08 03 55 DC 52 50 E8 89 FE FF FF }
	condition:
		$a0 at pe.entry_point
}