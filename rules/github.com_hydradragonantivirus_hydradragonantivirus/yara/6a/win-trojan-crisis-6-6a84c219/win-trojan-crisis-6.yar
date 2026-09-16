rule Win_Trojan_Crisis_6
{
strings:
	$a0 = { 364561717946666f2e7a494b }


condition:
	$a0
}