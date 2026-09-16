rule Win_Trojan_V127_2
{
strings:
	$a0 = { 7f00f3a4bad400b41acd21ba7901b4 }


condition:
	$a0
}