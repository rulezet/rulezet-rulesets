rule Win_Trojan_Ping_2
{
strings:
	$a0 = { e4cd138026f87d808b1ef97d0e582d }


condition:
	$a0
}