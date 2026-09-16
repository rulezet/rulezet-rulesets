rule Win_Trojan_Sistor_9
{
strings:
	$a0 = { 4033d2b9c10be8d7003bc1741b2e8b16b20b2e8b0eb00bb80042e8c300b440b90000e8bb00eb29 }


condition:
	$a0
}