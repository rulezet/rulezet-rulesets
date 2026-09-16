rule Win_Trojan_Shirley_1
{
strings:
	$a0 = { 3ea1a6c72ea3700e3ea1a8c72ea3720e3ec706a6c7f3 }


condition:
	$a0
}