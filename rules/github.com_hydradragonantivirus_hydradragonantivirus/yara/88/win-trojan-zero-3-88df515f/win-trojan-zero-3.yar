rule Win_Trojan_Zero_3
{
strings:
	$a0 = { cd602ec606250601902e803e2606 }


condition:
	$a0
}