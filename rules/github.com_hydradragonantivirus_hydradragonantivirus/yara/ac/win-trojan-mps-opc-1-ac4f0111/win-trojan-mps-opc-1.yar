rule Win_Trojan_MPS_OPC_1
{
strings:
	$a0 = { cd215e8bfe81c72d0232c0b94000f2ae4fc7055c00b9 }


condition:
	$a0
}