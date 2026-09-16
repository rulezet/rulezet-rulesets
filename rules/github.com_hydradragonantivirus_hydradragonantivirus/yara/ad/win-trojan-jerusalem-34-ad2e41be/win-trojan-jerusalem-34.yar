rule Win_Trojan_Jerusalem_34
{
strings:
	$a0 = { ae263805e0f98bd783c203061f0e07b8004b9c2eff1e }


condition:
	$a0
}