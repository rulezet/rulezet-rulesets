rule Win_Trojan_JapanXmas_1
{
strings:
	$a0 = { 01e800005f83ef058bef81c5580389 }


condition:
	$a0
}