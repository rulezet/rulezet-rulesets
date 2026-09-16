rule Win_Trojan_Xany_1
{
strings:
	$a0 = { 6b018db6e501bf0001a5a4b41a8d96e801cd21b44e8d96dc01cd2173079090bb0001ffe38d960602b8023dcd21 }


condition:
	$a0
}