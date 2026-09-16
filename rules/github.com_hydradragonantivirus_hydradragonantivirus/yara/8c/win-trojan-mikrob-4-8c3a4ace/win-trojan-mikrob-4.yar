rule Win_Trojan_Mikrob_4
{
strings:
	$a0 = { 6e61736b6f640b9b1000050052696768 }


condition:
	$a0
}