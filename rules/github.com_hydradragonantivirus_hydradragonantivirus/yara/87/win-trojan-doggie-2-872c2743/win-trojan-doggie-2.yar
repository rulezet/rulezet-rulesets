rule Win_Trojan_Doggie_2
{
strings:
	$a0 = { 0200550000000000ffff6a08000037010000030000000103 }


condition:
	$a0
}