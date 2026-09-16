rule Win_Trojan_Grither_4
{
strings:
	$a0 = { 8ed8b002b9a00033d2bb0000cd26 }


condition:
	$a0
}