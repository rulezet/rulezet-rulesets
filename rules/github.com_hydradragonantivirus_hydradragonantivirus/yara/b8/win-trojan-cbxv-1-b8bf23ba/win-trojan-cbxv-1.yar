rule Win_Trojan_Cbxv_1
{
strings:
	$a0 = { 881e1a0488daba23040e1f2e8b1e1b04b92303b440cd21724c33c0e879002ec6060301772ec606 }


condition:
	$a0
}