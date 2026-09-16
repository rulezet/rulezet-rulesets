rule Win_Trojan_Israel_2
{
strings:
	$a0 = { d02ea32f012e892631018cc88ed0bc4701fb1e06165053 }


condition:
	$a0
}