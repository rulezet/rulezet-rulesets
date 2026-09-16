rule Win_Trojan_GeldWash_1
{
strings:
	$a0 = { 1642018a364d018a2e4e018a0e4f01a04101bb001006530733dbcd1307730fb400cd13fe0e }


condition:
	$a0
}