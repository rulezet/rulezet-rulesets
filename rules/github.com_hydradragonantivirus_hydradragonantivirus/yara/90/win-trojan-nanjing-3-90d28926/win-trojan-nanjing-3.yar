rule Win_Trojan_Nanjing_3
{
strings:
	$a0 = { 4c00b4ffcd2180fc00751f2ea107000510002e8b1e }


condition:
	$a0
}