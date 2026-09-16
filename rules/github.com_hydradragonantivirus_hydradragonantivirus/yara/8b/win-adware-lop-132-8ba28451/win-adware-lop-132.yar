rule Win_Adware_Lop_132
{
strings:
	$a0 = { e800000000b8????????5b03c3ffe0 }

	$a1 = { 8a1732141888174083f8057c0233c047e2ee }


condition:
	$a0 and $a1
}