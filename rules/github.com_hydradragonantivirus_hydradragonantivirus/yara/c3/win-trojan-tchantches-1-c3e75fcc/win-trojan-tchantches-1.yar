rule Win_Trojan_Tchantches_1
{
strings:
	$a0 = { 2e8b16de0d81fb9a037503bac5af2e311783c3023bd9 }


condition:
	$a0
}