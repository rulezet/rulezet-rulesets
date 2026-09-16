rule Win_Trojan_Vacsina_3
{
strings:
	$a0 = { b450cd215b2e8c0e36002e8b162c }


condition:
	$a0
}