rule Win_Trojan_C_11
{
strings:
	$a0 = { e4cf8a144680f2fe7406b406cd21eb }


condition:
	$a0
}