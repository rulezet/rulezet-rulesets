rule Win_Trojan_Trivial_10
{
strings:
	$a0 = { 2a00b44e33c98bd6cd217215b8023dba9e00cd2193b440b1248bd6cd21b44febe7 }


condition:
	$a0
}