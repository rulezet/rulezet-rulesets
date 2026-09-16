import "pe"
rule _Simple_UPX_Cryptor_v3042005_multi_layer_encryption__MANtiCORE_
{
	meta:
		description = "Simple UPX Cryptor v30.4.2005 [multi layer encryption] --> MANtiCORE"
	strings:
		$0 = {60 B8 ?? ?? ?? 00 B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3}
		$1 = {60 B8 ?? ?? ?? ?? B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? ?? C3}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}