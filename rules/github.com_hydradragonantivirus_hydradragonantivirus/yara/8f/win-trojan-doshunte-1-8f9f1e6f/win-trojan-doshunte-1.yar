rule Win_Trojan_Doshunte_1
{
strings:
	$a0 = { 2acd2181fa1a06754fb002b9800033d2cd267244bb3901 }


condition:
	$a0
}