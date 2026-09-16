rule Win_Trojan_Leprosy_27
{
strings:
	$a0 = { 3f01908a2790322608019088274381fbb0037eefc3 }


condition:
	$a0
}