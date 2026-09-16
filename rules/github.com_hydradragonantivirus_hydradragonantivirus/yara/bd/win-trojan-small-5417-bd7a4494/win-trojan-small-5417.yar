rule Win_Trojan_Small_5417
{
strings:
	$a0 = { eb01490bc975fb }


condition:
	$a0
}