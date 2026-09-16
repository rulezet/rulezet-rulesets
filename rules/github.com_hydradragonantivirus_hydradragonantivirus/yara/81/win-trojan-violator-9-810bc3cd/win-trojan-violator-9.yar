rule Win_Trojan_Violator_9
{
strings:
	$a0 = { f283c668bf0001b90300f3a48bf2b80fffcd213d0101 }


condition:
	$a0
}