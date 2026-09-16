rule Win_Trojan_BlackJec_5
{
strings:
	$a0 = { b42acd2180fe09751a8d161402b409cd21b419cd218ad0b405b101b500b600b010cd13b98000be8000bf7ffff3a48d0633028bc82d0001a3fa00030e3102 }


condition:
	$a0
}