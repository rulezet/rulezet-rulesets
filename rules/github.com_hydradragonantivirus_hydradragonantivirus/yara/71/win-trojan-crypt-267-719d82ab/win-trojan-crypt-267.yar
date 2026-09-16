rule Win_Trojan_Crypt_267
{
strings:
	$a0 = { 66b9ffffeb1166b8004ccd2168e9000000e896dcfaffcce2eb484885d285c0bb }


condition:
	$a0
}