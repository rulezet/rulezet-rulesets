rule Win_Trojan_Small_4109
{
strings:
	$a0 = { e84b0000000f340538676202e80b00000083c50439 }


condition:
	$a0
}