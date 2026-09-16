rule Win_Trojan_Packed_74
{
strings:
	$a0 = { e80000000083042405c3 }

	$a1 = { e80000000083c404 }


condition:
	$a0 and $a1
}