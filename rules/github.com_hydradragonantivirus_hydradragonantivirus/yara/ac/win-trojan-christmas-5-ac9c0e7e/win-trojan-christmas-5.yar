rule Win_Trojan_Christmas_5
{
strings:
	$a0 = { fce80300e97d05505156be5900b91c0990d1e98ae1 }


condition:
	$a0
}