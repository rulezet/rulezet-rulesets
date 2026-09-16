rule Win_Trojan_Zero_7
{
strings:
	$a0 = { b800b88ed8bb00008a073c307502b04f88074343 }


condition:
	$a0
}