rule Win_Trojan_Zamol_2
{
strings:
	$a0 = { e02e830ec3071ef9c332c0cf9c2eff1ea307fac39c57bfbd072ea07a070c352e30054781ff69 }


condition:
	$a0
}