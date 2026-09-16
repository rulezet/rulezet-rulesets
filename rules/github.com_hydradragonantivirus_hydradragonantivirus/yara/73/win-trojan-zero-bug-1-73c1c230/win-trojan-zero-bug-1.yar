rule Win_Trojan_Zero_Bug_1
{
strings:
	$a0 = { 062b060090b435b060cd21bb0001 }


condition:
	$a0
}