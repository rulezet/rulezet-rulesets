rule Win_Trojan_Opal_2
{
strings:
	$a0 = { 408cc98ed9baf7fdb903002e8b1e1afecd21b457b0012e8b1e1afe2e8b0e0bfe2e8b1610fecd21 }


condition:
	$a0
}