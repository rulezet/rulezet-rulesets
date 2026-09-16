rule Win_Trojan_Whale_12
{
strings:
	$a0 = { 1f58e82b0093b9c31183eb1e8a17 }


condition:
	$a0
}