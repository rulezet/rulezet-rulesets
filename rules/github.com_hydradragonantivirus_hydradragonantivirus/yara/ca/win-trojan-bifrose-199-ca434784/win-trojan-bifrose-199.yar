rule Win_Trojan_Bifrose_199
{
strings:
	$a0 = { b7dae1d5cd6d8289a845d1ec60ecad64addb37b9f4a50ae284b1cdf8df6aa4937fb15829fea6e007bee457b12b12119f2654067cd072448abe654d46a0479a8f966cd68769cc44c410755ff4a6e8 }


condition:
	$a0
}