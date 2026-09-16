rule Win_Trojan_Amilia_1
{
strings:
	$a0 = { 1f81eed704b94e0641f3a4b462cd214b }


condition:
	$a0
}