rule _UPX_V194__Markus_Oberhumer__Laszlo_Molnar__John_Reiser_
{
	meta:
		description = "UPX V1.94 -> Markus Oberhumer & Laszlo Molnar & John Reiser"
	strings:
		$0 = {FF D5 80 A7 ?? ?? ?? ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9}
	condition:
		$0
}