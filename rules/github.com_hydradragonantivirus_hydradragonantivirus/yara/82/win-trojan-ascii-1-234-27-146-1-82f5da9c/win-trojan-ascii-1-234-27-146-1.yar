rule Win_Trojan_Ascii_1_234_27_146_1
{
strings:
	$a0 = { 312e3233342e32372e313436 }


condition:
	$a0
}