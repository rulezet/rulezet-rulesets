rule Win_Trojan_Xaxa_1
{
strings:
	$a0 = { 0e0190b90303902e8ab630042e8a279032e6902e8827904390e2f190c3 }


condition:
	$a0
}