rule Win_Trojan_Small_4156
{
strings:
	$a0 = { 81ebf92f414c81c3f92f414c895c24fc }


condition:
	$a0
}