rule Win_Trojan_Korea_1
{
strings:
	$a0 = { c6067f010133c0508ec0b8007c50 }


condition:
	$a0
}