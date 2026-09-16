rule Win_Trojan_Leprosy_44
{
strings:
	$a0 = { 0100c3bb31018a273226060188274381fbcb03 }


condition:
	$a0
}