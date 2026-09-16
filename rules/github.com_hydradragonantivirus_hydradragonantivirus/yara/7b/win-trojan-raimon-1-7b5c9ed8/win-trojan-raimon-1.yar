rule Win_Trojan_Raimon_1
{
strings:
	$a0 = { ba0001b43080c410cd21fe06e204e80100c3bb5e01 }


condition:
	$a0
}