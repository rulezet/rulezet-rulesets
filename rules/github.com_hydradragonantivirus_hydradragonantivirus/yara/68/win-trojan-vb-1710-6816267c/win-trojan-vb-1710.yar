rule Win_Trojan_VB_1710
{
strings:
	$a0 = { 5a9984000000000000010000004578706c69 }


condition:
	$a0
}