rule Win_Trojan_Plovdiv_2
{
strings:
	$a0 = { 1f80fa1e750626816f1de803079d5a5beb02cd32ca02 }


condition:
	$a0
}