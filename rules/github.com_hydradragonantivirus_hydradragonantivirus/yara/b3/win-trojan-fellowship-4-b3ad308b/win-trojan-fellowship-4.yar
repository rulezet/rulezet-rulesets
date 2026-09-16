rule Win_Trojan_Fellowship_4
{
strings:
	$a0 = { f502e83a00b60ae84a00ba1403382f }


condition:
	$a0
}