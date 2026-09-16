rule Win_Trojan_Philis_130
{
strings:
	$a0 = { 3bda740275006057d3cf5fe800000000 }


condition:
	$a0
}