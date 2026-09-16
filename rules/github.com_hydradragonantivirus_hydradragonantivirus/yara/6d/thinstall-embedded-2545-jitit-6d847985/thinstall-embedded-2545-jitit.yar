import "pe"
rule _Thinstall_Embedded_2545__Jitit_
{
	meta:
		description = "Thinstall Embedded 2.545 -> Jitit"
	strings:
		$0 = {E8 F2 FF FF FF 50 68 ?? ?? ?? ?? 68 40 1B 00 00 E8 42 FF FF FF E9 9D FF FF FF 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}