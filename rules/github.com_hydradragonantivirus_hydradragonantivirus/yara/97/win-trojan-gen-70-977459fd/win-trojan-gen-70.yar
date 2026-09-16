rule Win_Trojan_Gen_70
{
strings:
	$a0 = { 5ee946005eb43db0028bd681c21e00 }


condition:
	$a0
}