rule Win_Trojan_Infector_4
{
strings:
	$a0 = { 01a0f3022ea20101a0f4022ea20201b90001bb00002e }


condition:
	$a0
}