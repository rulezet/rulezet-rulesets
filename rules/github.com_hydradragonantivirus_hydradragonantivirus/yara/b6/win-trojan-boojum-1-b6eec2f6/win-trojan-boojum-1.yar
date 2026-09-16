rule Win_Trojan_Boojum_1
{
strings:
	$a0 = { b94e01fcf3a4061f31d2b82125cd }


condition:
	$a0
}