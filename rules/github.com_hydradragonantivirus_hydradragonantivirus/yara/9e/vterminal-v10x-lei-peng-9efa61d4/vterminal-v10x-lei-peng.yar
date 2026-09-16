import "pe"
rule _Vterminal_V10X__Lei_Peng_
{
	meta:
		description = "Vterminal V1.0X -> Lei Peng"
	strings:
		$0 = {E8 00 00 00 00 58 05 ?? ?? ?? ?? 9C 50 C2 04 00}
	condition:
		$0 at pe.entry_point
}