import "pe"
rule _aPack_098__099_COM_
{
	meta:
		description = "aPack 0.98 - 0.99 [COM]"
	strings:
		$0 = {BE 0D 01 BF 00 7F 8B CF FC 57 F3 A4 C3 BF 00 01 57}
	condition:
		$0 at pe.entry_point
}