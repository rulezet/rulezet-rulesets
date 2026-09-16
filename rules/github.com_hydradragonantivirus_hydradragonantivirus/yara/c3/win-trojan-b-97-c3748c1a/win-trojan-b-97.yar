rule Win_Trojan_B_97
{
strings:
	$a0 = { 47cd13ff364c008f06c37cff364e008f06c57ca113044848a31304 }


condition:
	$a0
}