rule Win_Trojan_E_33
{
strings:
	$a0 = { 75028bdacd2f2e8916e7022e8c1ee9022e8e1e2c00 }


condition:
	$a0
}