rule Win_Spyware_ye_170
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]a775b106c2e194c6e89538a2c2e79f }


condition:
	$a0
}