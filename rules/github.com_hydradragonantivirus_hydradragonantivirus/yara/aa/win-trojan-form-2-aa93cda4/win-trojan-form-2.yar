rule Win_Trojan_Form_2
{
strings:
	$a0 = { d3e08ec033ffb9ff00fcf3a506b8 }


condition:
	$a0
}