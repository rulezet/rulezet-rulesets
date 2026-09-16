rule Win_Trojan_Remut_2
{
strings:
	$a0 = { ff01ba48eeb9a00f03c8b440cd2132c0e8790056575355e86803b98a04251f0003c8be0501bf30 }


condition:
	$a0
}