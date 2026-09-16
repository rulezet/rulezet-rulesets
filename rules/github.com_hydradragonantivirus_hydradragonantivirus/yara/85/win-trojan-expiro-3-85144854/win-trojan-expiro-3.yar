rule Win_Trojan_Expiro_3
{
strings:
	$a0 = { 60e84069020061 }


condition:
	$a0
}