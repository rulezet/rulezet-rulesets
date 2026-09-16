rule Win_Trojan_Small_4340
{
strings:
	$a0 = { 5657[0-255]81c00100000081e889c026260589362726535e }


condition:
	$a0
}