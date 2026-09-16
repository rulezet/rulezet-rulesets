import "pe"
rule _UPX_051__072_COM_
{
	meta:
		description = "UPX 0.51 - 0.72 [COM]"
	strings:
		$0 = {B9 00 00 BE 00 00 BF C0 FF FD F3 A4 FC F7 E1 93 87 F7 83 EE 00 19 ED 57}
	condition:
		$0 at pe.entry_point
}