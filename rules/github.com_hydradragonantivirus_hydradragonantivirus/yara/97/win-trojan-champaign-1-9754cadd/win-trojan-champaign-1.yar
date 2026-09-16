rule Win_Trojan_Champaign_1
{
strings:
	$a0 = { b61d013e8b961e04b9800131144646e2fac3 }


condition:
	$a0
}