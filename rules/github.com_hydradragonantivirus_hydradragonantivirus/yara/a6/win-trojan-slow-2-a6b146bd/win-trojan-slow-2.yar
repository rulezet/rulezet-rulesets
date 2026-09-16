rule Win_Trojan_Slow_2
{
strings:
	$a0 = { e800005e8bde909081c61b00b990062e }


condition:
	$a0
}