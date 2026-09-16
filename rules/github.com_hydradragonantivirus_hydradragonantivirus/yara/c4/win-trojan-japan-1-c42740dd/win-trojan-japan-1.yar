rule Win_Trojan_Japan_1
{
strings:
	$a0 = { e4cf50528a144680f2fe7406b406cd21ebf25a58c3 }


condition:
	$a0
}