import "pe"
rule _XPack_167_
{
	meta:
		description = "XPack 1.67"
	strings:
		$0 = {B8 8C D3 15 33 75 81 3E E8 0F 00 9A E8 F9 FF 9A 9C EB 01 9A 59 80 CD 01 51 9D EB}
	condition:
		$0 at pe.entry_point
}