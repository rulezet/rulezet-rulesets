rule Win_Trojan_Form_3
{
strings:
	$a0 = { b9ff00fcf3a506b89a0050bbfe01b80102 }


condition:
	$a0
}