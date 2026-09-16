rule Win_Trojan_Dgen_1
{
strings:
	$a0 = { 84008bdebf420390a5a5fac7075a02 }


condition:
	$a0
}