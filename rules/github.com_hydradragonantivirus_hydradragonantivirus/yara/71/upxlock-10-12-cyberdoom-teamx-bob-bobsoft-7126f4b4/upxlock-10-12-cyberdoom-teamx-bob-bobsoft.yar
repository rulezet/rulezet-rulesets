import "pe"
rule _UpxLock_10__12__CyberDoom__TeamX__BoB__BobSoft_
{
	meta:
		description = "Upx-Lock 1.0 - 1.2 --> CyberDoom / Team-X & BoB / BobSoft"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61}
	condition:
		$0 at pe.entry_point
}