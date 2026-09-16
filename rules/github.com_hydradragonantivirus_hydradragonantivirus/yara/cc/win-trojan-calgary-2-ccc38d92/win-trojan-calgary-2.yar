rule Win_Trojan_Calgary_2
{
strings:
	$a0 = { e8000000005f8bef }


condition:
	$a0
}