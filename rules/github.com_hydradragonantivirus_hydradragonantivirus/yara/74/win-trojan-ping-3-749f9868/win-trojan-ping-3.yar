rule Win_Trojan_Ping_3
{
strings:
	$a0 = { cd138026f87d808b1ef97d0e07bd }


condition:
	$a0
}