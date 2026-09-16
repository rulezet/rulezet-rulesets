rule Win_Trojan_Tequila_1
{
strings:
	$a0 = { b96009[2-3]8a1789c730144643????81fb????7204 }


condition:
	$a0
}