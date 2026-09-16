rule Win_Trojan_Jindra_2
{
strings:
	$a0 = { b9fa00fdf890e8 }

	$a1 = { f83107f94e43fdf84a47f5f842e2f1c3 }


condition:
	$a0 and $a1
}