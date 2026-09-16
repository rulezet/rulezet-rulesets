rule Win_Trojan_Herms_1
{
strings:
	$a0 = { 08008ed8be0000e82100b202e83100e82e00e82b00fec280fa0275f0be9000e80900bed000e80300eb29905052ac0a }


condition:
	$a0
}