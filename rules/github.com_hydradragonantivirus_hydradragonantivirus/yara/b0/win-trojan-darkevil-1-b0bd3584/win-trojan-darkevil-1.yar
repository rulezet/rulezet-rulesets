rule Win_Trojan_DarkEvil_1
{
strings:
	$a0 = { 023de89eff720a8bd8e82e00b43ee8 }


condition:
	$a0
}