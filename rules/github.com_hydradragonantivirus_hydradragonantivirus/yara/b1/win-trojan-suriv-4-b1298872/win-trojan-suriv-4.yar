rule Win_Trojan_Suriv_4
{
strings:
	$a0 = { b104bcb1041e0783c30fd1ebd1ebd1ebd1eb891e0901cd }


condition:
	$a0
}