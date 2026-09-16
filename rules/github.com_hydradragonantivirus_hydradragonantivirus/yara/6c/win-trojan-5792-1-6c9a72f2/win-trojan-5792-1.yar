rule Win_Trojan_5792_1
{
strings:
	$a0 = { be00ff16578dbe5ce81657b8a016508dbefcfe16579a25 }


condition:
	$a0
}