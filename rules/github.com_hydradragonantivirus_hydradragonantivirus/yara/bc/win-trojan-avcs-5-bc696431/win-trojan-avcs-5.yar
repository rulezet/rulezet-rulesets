rule Win_Trojan_Avcs_5
{
strings:
	$a0 = { e800005d81ed????8db6????568bfeb977008b96????fcad33c2abe2fac3 }


condition:
	$a0
}