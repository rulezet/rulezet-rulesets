rule Win_Trojan_Small_162
{
strings:
	$a0 = { fce800005e83ee04bf0001570e0e5683c63ea4a55eb821008ec033ffa6741c4e4fb9b200f3a450b435cd211f891eb2008c06b400b425ba4400cd211f07c3 }


condition:
	$a0
}