rule Win_Trojan_ATT_1
{
strings:
	$a0 = { 0300ba77028bf2cd21803c4d7431 }


condition:
	$a0
}