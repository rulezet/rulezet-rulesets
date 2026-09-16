rule Win_Trojan_Gen_61
{
strings:
	$a0 = { 0500cd2f534b4b26881db81612cd }


condition:
	$a0
}