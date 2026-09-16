rule Win_Trojan_Kvex_1
{
strings:
	$a0 = { b800004100681c94400064ff35000000006489250000000066 }


condition:
	$a0
}