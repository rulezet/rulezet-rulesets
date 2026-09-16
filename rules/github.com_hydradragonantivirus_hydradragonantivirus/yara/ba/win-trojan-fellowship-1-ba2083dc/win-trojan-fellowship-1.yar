rule Win_Trojan_Fellowship_1
{
strings:
	$a0 = { 02e83a00b60ae84a00ba1403e82f }


condition:
	$a0
}