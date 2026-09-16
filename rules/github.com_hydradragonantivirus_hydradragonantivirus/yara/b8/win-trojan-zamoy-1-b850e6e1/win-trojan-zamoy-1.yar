rule Win_Trojan_Zamoy_1
{
strings:
	$a0 = { 4d75bc2e8b3e06018b760081c68c0203f7817c1a }


condition:
	$a0
}