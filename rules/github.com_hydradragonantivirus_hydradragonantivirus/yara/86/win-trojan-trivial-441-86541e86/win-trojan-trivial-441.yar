rule Win_Trojan_Trivial_441
{
strings:
	$a0 = { 423dcd2193b420d0e4b182ba0001cd21c3b42ccd218aca }


condition:
	$a0
}