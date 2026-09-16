rule Win_Trojan_NTZ_5
{
strings:
	$a0 = { cd21888e2d01b92f018db65e018dbe7502a48a86750232862d01888675028d7cff8db67502a4 }


condition:
	$a0
}