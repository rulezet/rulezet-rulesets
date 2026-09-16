rule Win_Trojan_CrazyImp_2
{
strings:
	$a0 = { e643b080e641b000e641e4210c02 }


condition:
	$a0
}