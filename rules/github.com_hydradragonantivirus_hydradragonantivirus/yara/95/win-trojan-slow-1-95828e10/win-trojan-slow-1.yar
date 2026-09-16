rule Win_Trojan_Slow_1
{
strings:
	$a0 = { 909081c61b00b990062e8034 }


condition:
	$a0
}