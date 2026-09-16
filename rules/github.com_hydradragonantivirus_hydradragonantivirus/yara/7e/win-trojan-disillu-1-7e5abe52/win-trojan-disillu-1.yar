rule Win_Trojan_Disillu_1
{
strings:
	$a0 = { 3a04bb1601b209e4812e30173317e481cd0143e2f2 }


condition:
	$a0
}