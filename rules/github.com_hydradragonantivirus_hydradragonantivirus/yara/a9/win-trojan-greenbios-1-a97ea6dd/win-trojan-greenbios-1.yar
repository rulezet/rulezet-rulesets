rule Win_Trojan_GreenBios_1
{
strings:
	$a0 = { 1e5904b9390490ba0001cd212e8f063705b802428b }


condition:
	$a0
}