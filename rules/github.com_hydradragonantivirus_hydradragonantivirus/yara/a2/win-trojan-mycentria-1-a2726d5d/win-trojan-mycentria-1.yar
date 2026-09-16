rule Win_Trojan_Mycentria_1
{
strings:
	$a0 = { 558bec83c4e4535633c08945e48945e8 }

	$a1 = { 2f616463656e747269612f616463656e747269612e6a73 }


condition:
	$a0 and $a1
}