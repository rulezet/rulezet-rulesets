rule Win_Trojan_Khizhnjak_21
{
strings:
	$a0 = { 01a02f032ea20101a030032ea20201b98000bb00002e }


condition:
	$a0
}