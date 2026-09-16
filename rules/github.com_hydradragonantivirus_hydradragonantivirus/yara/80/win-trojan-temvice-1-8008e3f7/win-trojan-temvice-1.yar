rule Win_Trojan_Temvice_1
{
strings:
	$a0 = { b8944d4000e8cbfcffff8b45fce8fbecffff506aff6a00e8cdf2ffff8bd868e8 }


condition:
	$a0
}