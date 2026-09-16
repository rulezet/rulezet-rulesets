rule Win_Trojan_Barys_1
{
strings:
	$a0 = { 72656d6f7665546872656174 }

	$a1 = { 72657475726e484b4355 }

	$a2 = { 72657475726e484b4c4d }

	$a3 = { 72657475726e44697273 }

	$a4 = { 47656e65726963426f74 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}