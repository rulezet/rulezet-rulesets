rule Win_Trojan_Punch_1
{
strings:
	$a0 = { e8000000005d81ed050000008b9dc6020000019dca020000 }


condition:
	$a0
}