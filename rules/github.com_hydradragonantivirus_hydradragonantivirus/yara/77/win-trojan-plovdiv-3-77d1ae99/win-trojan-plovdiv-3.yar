rule Win_Trojan_Plovdiv_3
{
strings:
	$a0 = { e21f80fa1e750626816f1de803075a5b9dca0200b41a5a }


condition:
	$a0
}