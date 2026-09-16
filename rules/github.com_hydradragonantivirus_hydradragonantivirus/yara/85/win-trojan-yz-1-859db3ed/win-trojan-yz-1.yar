rule Win_Trojan_YZ_1
{
strings:
	$a0 = { fc8db76201b2ec8d8f05062bce2e301446e2fafbc3595a }


condition:
	$a0
}