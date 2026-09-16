rule Win_Trojan_Gotcha_1
{
strings:
	$a0 = { fc2e80bf39010074128cd80510002e03871d }


condition:
	$a0
}