rule Win_Trojan_Packed_38
{
strings:
	$a0 = { 81f6ff47204281f6ff472042575681ef }


condition:
	$a0
}