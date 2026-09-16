rule Win_Trojan_Duke_7
{
strings:
	$a0 = { 6b652f534d46008dbe00ff165731c0509a58066800bf1e2a1e57b8ff00509a0f086800c6061c }


condition:
	$a0
}