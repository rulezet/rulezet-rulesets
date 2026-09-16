rule Win_Trojan_Jerusalem_38
{
strings:
	$a0 = { e0f98bd783c203b8004b061f0e07bb21009c2eff1e }


condition:
	$a0
}