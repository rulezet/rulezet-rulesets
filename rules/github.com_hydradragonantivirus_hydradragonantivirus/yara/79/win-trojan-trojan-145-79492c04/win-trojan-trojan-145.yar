rule Win_Trojan_Trojan_145
{
strings:
	$a0 = { e80000b9580d5b81eba90d2e80370243 }


condition:
	$a0
}