rule Win_Trojan_Nocopy_2
{
strings:
	$a0 = { 0901000056016410e9000c000005005a22c7d8e0ca4fcaa81b0be12c09b06607b36c0b22c38217160bbd49c4f4 }


condition:
	$a0
}