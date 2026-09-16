rule Win_Trojan_Peed_324
{
strings:
	$a0 = { ba45460500e89b00000068247700005981c1505f000081c124770000baffbbbf }


condition:
	$a0
}