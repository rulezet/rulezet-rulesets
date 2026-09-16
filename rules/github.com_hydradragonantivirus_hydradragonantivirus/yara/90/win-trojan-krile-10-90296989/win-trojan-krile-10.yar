rule Win_Trojan_Krile_10
{
strings:
	$a0 = { c847c6ae3d5d4c876a38e477ee087a8877dc4bb88cd3153375813ee80f009ae8f9ff9a9ceb019a }


condition:
	$a0
}