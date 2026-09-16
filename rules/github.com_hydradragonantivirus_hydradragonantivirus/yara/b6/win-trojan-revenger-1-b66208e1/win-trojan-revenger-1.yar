rule Win_Trojan_Revenger_1
{
strings:
	$a0 = { cd213c0d7549b007e670e4713c297404680001c3b9 }


condition:
	$a0
}