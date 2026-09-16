rule Win_Trojan_Plovdiv_4
{
strings:
	$a0 = { 1f80fa1e750626816f1de80307 }


condition:
	$a0
}