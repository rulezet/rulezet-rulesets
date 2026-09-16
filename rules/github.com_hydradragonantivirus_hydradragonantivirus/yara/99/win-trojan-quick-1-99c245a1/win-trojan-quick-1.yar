rule Win_Trojan_Quick_1
{
strings:
	$a0 = { 01030055e003000100ffff0000000087020000080000006a08 }


condition:
	$a0
}