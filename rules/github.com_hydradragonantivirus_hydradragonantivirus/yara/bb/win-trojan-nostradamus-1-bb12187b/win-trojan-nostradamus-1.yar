rule Win_Trojan_Nostradamus_1
{
strings:
	$a0 = { 010400550000000000010076080000de030000030000007608 }


condition:
	$a0
}