rule Win_Trojan_Khizhnjak_24
{
strings:
	$a0 = { 01a02f032ea20101a030032ea20201b99000bb00002e }


condition:
	$a0
}