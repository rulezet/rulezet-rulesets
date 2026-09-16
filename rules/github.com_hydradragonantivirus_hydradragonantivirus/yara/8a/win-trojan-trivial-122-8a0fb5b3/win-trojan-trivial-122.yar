rule Win_Trojan_Trivial_122
{
strings:
	$a0 = { 2e2a00b44e8bd6b120cd2192b29eb8023dcd2193b4408bd6cd21c3 }


condition:
	$a0
}