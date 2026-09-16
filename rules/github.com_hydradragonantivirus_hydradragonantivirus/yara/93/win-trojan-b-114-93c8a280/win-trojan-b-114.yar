rule Win_Trojan_B_114
{
strings:
	$a0 = { 7c33fffa8ed78be6fb9a3000c007 }


condition:
	$a0
}