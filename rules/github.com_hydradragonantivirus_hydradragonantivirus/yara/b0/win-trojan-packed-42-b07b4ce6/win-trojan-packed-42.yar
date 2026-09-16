rule Win_Trojan_Packed_42
{
strings:
	$a0 = { 5800e8 }

	$a1 = { 45008b550483c5 }


condition:
	$a0 and $a1
}