import "pe"
rule _ExePack_10___
{
	meta:
		description = "ExePack 1.0 -> ��ҹ�ʺ�"
	strings:
		$0 = {60 E8 36 FE FF FF C3 90}
	condition:
		$0 at pe.entry_point
}