rule Win_Trojan_Vgen_135
{
strings:
	$a0 = { 51cd218ec3263b1e160075288bda8a0750b42fcd21583cff750383c307268b4717251f003d1f00 }


condition:
	$a0
}