rule Win_Trojan_Octubre_1
{
strings:
	$a0 = { b4ff055df872fc81ed0a001e060e0e1f07b9a3068d }


condition:
	$a0
}