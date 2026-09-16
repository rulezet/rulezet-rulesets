rule Win_Trojan_Zamol_5
{
strings:
	$a0 = { 830ebd100190f9c332c090cf9c2eff1e460890fac39c5790bfb6102ea01608900caa2e300547 }


condition:
	$a0
}