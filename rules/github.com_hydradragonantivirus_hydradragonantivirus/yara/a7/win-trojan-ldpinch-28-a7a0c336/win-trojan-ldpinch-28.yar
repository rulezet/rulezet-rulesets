rule Win_Trojan_LdPinch_28
{
strings:
	$a0 = { 544f2726623d506173736573206672efa0fe6f102070696e636826633d00c03a2f2f77dbfeff6f00 }


condition:
	$a0
}