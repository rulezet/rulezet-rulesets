rule Win_Trojan_Tricks_6
{
strings:
	$a0 = { be0000e88700155e55eb155e2beb5ea4677e53ebd92327cb98b452e8d75074ea27cb61325ed5677e55eb53 }


condition:
	$a0
}