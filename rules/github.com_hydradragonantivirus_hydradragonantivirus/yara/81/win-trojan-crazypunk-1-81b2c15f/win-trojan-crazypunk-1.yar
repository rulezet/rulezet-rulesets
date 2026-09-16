rule Win_Trojan_CrazyPunk_1
{
strings:
	$a0 = { e5000e8dbc22015733db8edbc606f004cb0e1feaf00400 }


condition:
	$a0
}