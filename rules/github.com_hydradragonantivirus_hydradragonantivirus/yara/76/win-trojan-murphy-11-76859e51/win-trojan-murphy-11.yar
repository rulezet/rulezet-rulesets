rule Win_Trojan_Murphy_11
{
strings:
	$a0 = { b8594bcd217203e926015e568bfe33c0 }


condition:
	$a0
}