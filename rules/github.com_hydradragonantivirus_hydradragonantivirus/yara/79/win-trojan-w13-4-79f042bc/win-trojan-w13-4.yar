rule Win_Trojan_W13_4
{
strings:
	$a0 = { 8b4f1683e11e83f91e74ec817f1a00fa }


condition:
	$a0
}