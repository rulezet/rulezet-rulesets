rule Win_Trojan_Murphy_1
{
strings:
	$a0 = { e80000b8594bcd217203e928015e56 }


condition:
	$a0
}