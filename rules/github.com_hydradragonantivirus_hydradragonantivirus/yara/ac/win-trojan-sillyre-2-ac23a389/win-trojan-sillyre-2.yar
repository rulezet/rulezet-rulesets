rule Win_Trojan_SillyRE_2
{
strings:
	$a0 = { fecd210ae4745b1e8cd8488ed88a160000c60600004d8b }


condition:
	$a0
}