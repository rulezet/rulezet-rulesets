rule Win_Trojan_Tepfer_61
{
strings:
	$a0 = { bb11010f1eb50acd21b8014ccd219090 }

	$a1 = { 6869732070 }

	$a2 = { 64657220 }

	$a3 = { 7874 }

	$a4 = { 004000 }

	$a5 = { 7365 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5
}