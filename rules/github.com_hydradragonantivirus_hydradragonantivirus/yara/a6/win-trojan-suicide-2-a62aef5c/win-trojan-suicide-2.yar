rule Win_Trojan_Suicide_2
{
strings:
	$a0 = { 1ee800005d81ed0701e80200eb41b9e8038db634012e8134 }


condition:
	$a0
}