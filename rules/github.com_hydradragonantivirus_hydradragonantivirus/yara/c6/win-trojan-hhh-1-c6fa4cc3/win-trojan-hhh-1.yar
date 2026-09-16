rule Win_Trojan_HHH_1
{
strings:
	$a0 = { 50b9fb0f8b1e010181c3150180370043e2fa }


condition:
	$a0
}