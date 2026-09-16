rule Win_Trojan_Serrelinda_1
{
strings:
	$a0 = { cd1326836f0e20268b87a80026894714268b87aa002689471626c7470820005157fcb95101 }


condition:
	$a0
}