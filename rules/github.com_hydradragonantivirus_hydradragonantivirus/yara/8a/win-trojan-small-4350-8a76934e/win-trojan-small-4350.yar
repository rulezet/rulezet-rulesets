rule Win_Trojan_Small_4350
{
strings:
	$a0 = { b800004000505b[0-255]81e889f226260589362726535e }


condition:
	$a0
}