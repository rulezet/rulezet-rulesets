rule Win_Trojan_PKZ_1
{
strings:
	$a0 = { 434f4d5ec6061d0100be3901b92400b000300446e2fb }


condition:
	$a0
}