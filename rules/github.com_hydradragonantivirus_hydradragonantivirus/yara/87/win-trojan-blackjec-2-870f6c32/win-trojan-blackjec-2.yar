rule Win_Trojan_BlackJec_2
{
strings:
	$a0 = { 90b42acd2180fe097519ba0e02b409cd21b419cd218ad0b405b101b500b600b010cd13b98000be8000bf7ffff3a4b82d028bc82d0001a3fa00030e2b02890e }


condition:
	$a0
}