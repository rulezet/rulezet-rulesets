rule Win_Trojan_HHH_2
{
strings:
	$a0 = { 50b9fd0f8b1e010181c3150180370043e2fa }


condition:
	$a0
}