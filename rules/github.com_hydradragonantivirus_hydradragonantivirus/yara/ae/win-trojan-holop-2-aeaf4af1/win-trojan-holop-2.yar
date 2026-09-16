rule Win_Trojan_Holop_2
{
strings:
	$a0 = { 6f6c6f702e62617401209a0000af005589e581ec0202bfba1e1e57bfbc1e1e57bfbe1e1e57bfc0 }


condition:
	$a0
}