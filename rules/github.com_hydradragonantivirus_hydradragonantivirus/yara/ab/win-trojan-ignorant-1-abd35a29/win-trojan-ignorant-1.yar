rule Win_Trojan_Ignorant_1
{
strings:
	$a0 = { 06ff4c0281049207e87af883c4088f44028f0405100096560e1fb97007b8 }


condition:
	$a0
}