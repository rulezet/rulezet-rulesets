rule Win_Trojan_Car_1
{
strings:
	$a0 = { 81c5fdfeb8cdabcd21734fe894017203e90300e80602fab82135cd21899e2c028c862e02 }


condition:
	$a0
}