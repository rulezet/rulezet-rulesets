rule Win_Trojan_Khizhnjak_38
{
strings:
	$a0 = { 01a0dd022ea20101a0de022ea20201b90001bb00002e }


condition:
	$a0
}