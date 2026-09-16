rule Win_Trojan_SillyC_230
{
strings:
	$a0 = { 9e0068923d58cd2193b6feb43fe83000803e9efeb4741368024258e81800896d0689fa68004258 }


condition:
	$a0
}