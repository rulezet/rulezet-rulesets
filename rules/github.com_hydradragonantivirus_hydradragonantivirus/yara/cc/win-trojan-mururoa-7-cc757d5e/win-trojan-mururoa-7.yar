rule Win_Trojan_Mururoa_7
{
strings:
	$a0 = { 55e80e00065660e866fd615ee8dafde9bcf2 }


condition:
	$a0
}