import "pe"
rule _UPX_020_COM_
{
	meta:
		description = "UPX 0.20 [COM]"
	strings:
		$0 = {B9 00 00 BE 00 00 BF C0 FF BD FF FF FD F3 A4 FC F7 E1 93 87 F7 83 C6 31 57 57 E9 3C FE 55 50 58 21 03 01 02 87}
	condition:
		$0 at pe.entry_point
}