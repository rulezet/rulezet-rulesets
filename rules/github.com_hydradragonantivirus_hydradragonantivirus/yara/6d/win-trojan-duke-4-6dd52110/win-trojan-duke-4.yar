rule Win_Trojan_Duke_4
{
strings:
	$a0 = { eb184d696e69484c4c43202863292062792044756b652f534d46e8cdfcbf0f030e57b82100 }


condition:
	$a0
}