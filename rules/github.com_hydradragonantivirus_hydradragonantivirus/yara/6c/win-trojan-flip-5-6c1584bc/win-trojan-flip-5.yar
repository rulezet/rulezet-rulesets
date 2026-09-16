rule Win_Trojan_Flip_5
{
strings:
	$a0 = { 923e1fb202b9d19b81c1506ceb0000976ec143eb }


condition:
	$a0
}