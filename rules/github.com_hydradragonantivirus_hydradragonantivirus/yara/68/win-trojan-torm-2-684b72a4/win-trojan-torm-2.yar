rule Win_Trojan_Torm_2
{
strings:
	$a0 = { cd21724180bcff004d7435b8024233c933d2cd212d04 }


condition:
	$a0
}