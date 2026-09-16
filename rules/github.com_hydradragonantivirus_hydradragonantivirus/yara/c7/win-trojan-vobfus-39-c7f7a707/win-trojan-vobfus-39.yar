rule Win_Trojan_Vobfus_39
{
strings:
	$a0 = { 6c750000000000000100000000000000000064696e6974726f }


condition:
	$a0
}