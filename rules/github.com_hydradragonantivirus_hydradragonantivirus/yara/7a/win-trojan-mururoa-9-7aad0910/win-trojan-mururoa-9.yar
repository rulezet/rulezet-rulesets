rule Win_Trojan_Mururoa_9
{
strings:
	$a0 = { 55e80e00065660e865fd615ee8d9fde9b6f2 }


condition:
	$a0
}