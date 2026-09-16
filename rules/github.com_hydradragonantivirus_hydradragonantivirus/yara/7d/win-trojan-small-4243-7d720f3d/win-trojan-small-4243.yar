rule Win_Trojan_Small_4243
{
strings:
	$a0 = { 8d9800??400053535f5d81c79c070000 }


condition:
	$a0
}