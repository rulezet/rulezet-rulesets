rule Win_Trojan_Arme_1
{
strings:
	$a0 = { 9e0139069c017431059b01a39901b80042e83a00b80057cd215251b90300b440ba9801cd21 }


condition:
	$a0
}