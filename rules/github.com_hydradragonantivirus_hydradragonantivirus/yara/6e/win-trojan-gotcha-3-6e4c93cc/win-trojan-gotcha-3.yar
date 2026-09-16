rule Win_Trojan_Gotcha_3
{
strings:
	$a0 = { dada74585251535056571e063d00 }


condition:
	$a0
}