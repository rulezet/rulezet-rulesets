rule Win_Trojan_LockCD_1
{
strings:
	$a0 = { 34070f0cdac3c2c1c0bfbebdbcbbbab9b8b7b6c4c3c2c1c0bfbebdbcbbbab9b30f0cb31f1e1d1c1b1a19181716d0cf }


condition:
	$a0
}