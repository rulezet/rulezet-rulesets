rule Win_Trojan_Estier_1
{
strings:
	$a0 = { bd1801e800005e81ee09012e8032ffe3044945ebf6 }


condition:
	$a0
}