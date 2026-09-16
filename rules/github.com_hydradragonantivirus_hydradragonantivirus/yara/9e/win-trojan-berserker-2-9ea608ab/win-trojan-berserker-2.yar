rule Win_Trojan_Berserker_2
{
strings:
	$a0 = { 8932fd8ae62acdbe38f2f6dff6d0f7d19e81e35c9702e78bcb02e580ec3bb6752ae980e50d80e8c79ff7d081e2 }


condition:
	$a0
}