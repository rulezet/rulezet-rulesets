rule Win_Trojan_Sality_1036
{
strings:
	$a0 = { 60e80c000000380e7b9f0992a6bab0da3b13e80c0200002be8fecaeb019c8bf55981fa8311 }


condition:
	$a0
}