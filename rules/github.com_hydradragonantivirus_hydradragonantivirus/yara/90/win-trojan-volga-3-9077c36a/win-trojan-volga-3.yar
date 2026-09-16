rule Win_Trojan_Volga_3
{
strings:
	$a0 = { be007c33fffa8ed78be6fbea3000c007 }


condition:
	$a0
}