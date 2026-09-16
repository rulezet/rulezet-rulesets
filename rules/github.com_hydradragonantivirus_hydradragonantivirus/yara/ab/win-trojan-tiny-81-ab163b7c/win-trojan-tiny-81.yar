rule Win_Trojan_Tiny_81
{
strings:
	$a0 = { acce0181c503018d94d0012bc9b44ecd21720fba9e00b8 }


condition:
	$a0
}