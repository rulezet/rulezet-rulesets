rule Win_Trojan_Bljec_3
{
strings:
	$a0 = { b9800090be800090bf7fff90f3a4b87a028bc82d0001a3fa00030e4802890ef80003c8890ef60090 }


condition:
	$a0
}