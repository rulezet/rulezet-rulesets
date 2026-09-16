import "pe"
rule _TPAV_Cryptor_V11__msaha_dev_
{
	meta:
		description = "TPAV Cryptor V1.1 -> msaha_dev"
	strings:
		$0 = {8D 85 08 FF FF FF 50 8D 85 C4 FE FF FF 50 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 8D 95 C0 FE FF FF 33 C0 E8 ?? ?? FF FF 8B 85 C0 FE FF FF E8 ?? ?? FF FF 50 6A 00 FF 15 2C ?? ?? 70}
	condition:
		$0 at pe.entry_point
}