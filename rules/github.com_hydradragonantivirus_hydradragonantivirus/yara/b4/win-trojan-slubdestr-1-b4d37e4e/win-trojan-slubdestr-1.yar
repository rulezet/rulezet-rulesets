rule Win_Trojan_Slubdestr_1
{
strings:
	$a0 = { 50535152061e80fc4c742e80fc4b7429eb1890b42c9c }


condition:
	$a0
}