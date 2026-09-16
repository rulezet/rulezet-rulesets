import "pe"
rule __22b__Shoooo_
{
	meta:
		description = "ܥ��ѹ�� 2.2b -> Shoooo"
	strings:
		$0 = {68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 11 55 07 8B EC B8 14 80 0E 03 E8 D1 09 00 0A 57 33 D2 FF 75 18 B9 E8 1F DE 16 81 C0 8D BD EE 7F FB F8}
	condition:
		$0 at pe.entry_point
}