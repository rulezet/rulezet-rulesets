rule Win_Trojan_Onehalf_1
{
strings:
	$a0 = { 798ae3bc680bf1b5751b86c60227372f73dc5c }


condition:
	$a0
}