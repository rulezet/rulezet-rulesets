rule Win_Trojan_Trojan_191
{
strings:
	$a0 = { e80000b84d4bcd217203e926015e56 }


condition:
	$a0
}