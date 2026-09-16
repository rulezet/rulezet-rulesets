rule Win_Trojan_Replico_6
{
strings:
	$a0 = { 3801b9b0012e8ab600032e8a2732e62e882743e2f5c3 }


condition:
	$a0
}