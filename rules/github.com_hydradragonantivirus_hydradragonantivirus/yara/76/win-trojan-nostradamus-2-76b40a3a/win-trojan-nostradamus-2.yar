rule Win_Trojan_Nostradamus_2
{
strings:
	$a0 = { 010300550000000000010076080000a1030000030000007608 }


condition:
	$a0
}