rule Win_Trojan_Khizhnjak_23
{
strings:
	$a0 = { 01a0bf022ea20101a0c0022ea20201b90001bb00002e }


condition:
	$a0
}