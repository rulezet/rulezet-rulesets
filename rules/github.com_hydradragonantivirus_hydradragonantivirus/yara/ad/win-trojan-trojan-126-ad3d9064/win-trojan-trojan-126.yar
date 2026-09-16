rule Win_Trojan_Trojan_126
{
strings:
	$a0 = { 1e068bf00592008bd88cc88ed8bf00018b47fd89058a }


condition:
	$a0
}