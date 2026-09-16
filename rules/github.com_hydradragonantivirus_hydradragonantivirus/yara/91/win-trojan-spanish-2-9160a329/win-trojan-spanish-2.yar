rule Win_Trojan_Spanish_2
{
strings:
	$a0 = { 1f8ed85bb43fb930059033d2cd21 }


condition:
	$a0
}