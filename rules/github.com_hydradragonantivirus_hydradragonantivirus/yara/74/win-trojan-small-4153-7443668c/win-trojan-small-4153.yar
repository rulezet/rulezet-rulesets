rule Win_Trojan_Small_4153
{
strings:
	$a0 = { cd2ae819000000e842000000816c0500 }


condition:
	$a0
}