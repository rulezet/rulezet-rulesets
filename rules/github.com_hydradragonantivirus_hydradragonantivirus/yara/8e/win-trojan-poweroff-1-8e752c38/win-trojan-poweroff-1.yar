rule Win_Trojan_PowerOff_1
{
strings:
	$a0 = { 408bfa2bd1b91e03cd2190730490eb1e903d1e037518b8 }


condition:
	$a0
}