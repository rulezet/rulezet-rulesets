rule Win_Trojan_Suriv_1
{
strings:
	$a0 = { bc85061e0783c30fd1ebd1ebd1ebd1eb891e0901cd }


condition:
	$a0
}