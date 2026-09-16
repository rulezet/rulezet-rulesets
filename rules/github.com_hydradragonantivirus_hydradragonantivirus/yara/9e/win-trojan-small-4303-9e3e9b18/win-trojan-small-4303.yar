rule Win_Trojan_Small_4303
{
strings:
	$a0 = { b800004000e91c00000081e889f226260589362726535e }


condition:
	$a0
}