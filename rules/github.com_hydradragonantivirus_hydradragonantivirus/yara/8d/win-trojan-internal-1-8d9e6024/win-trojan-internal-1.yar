rule Win_Trojan_Internal_1
{
strings:
	$a0 = { 8d162900cd217303e91401a32700 }


condition:
	$a0
}