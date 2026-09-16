rule Win_Trojan_Jerusalem_44
{
strings:
	$a0 = { e0f98bd783c202b8004b061f0e07bb9a049c2eff1e }


condition:
	$a0
}