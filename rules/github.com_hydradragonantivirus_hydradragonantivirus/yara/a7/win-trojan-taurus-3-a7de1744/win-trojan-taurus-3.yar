rule Win_Trojan_Taurus_3
{
strings:
	$a0 = { bac9001e061fcd211fbf14033e8b0347473e8b1b47 }


condition:
	$a0
}