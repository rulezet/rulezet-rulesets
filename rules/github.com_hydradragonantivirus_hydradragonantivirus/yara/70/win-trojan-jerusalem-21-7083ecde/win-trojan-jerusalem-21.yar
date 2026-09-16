rule Win_Trojan_Jerusalem_21
{
strings:
	$a0 = { f2ae263805e0f98bd783c203bb6602061f0e07b8004b9c }


condition:
	$a0
}