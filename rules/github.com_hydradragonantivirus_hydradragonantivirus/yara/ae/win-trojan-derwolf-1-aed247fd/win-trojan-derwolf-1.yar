rule Win_Trojan_DerWolf_1
{
strings:
	$a0 = { cd2172259090b43cbaa10433c9cd2193b440ba2001b99008cd21b43ecd21b44ebab304cd21 }


condition:
	$a0
}