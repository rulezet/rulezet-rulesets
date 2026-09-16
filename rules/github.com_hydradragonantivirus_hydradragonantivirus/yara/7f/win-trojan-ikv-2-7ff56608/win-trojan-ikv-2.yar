rule Win_Trojan_IKV_2
{
strings:
	$a0 = { faba2c0003d78bdab41acd21bd0000 }


condition:
	$a0
}