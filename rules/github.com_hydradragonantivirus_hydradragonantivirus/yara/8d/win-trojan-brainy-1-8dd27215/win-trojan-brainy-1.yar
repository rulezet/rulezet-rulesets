rule Win_Trojan_Brainy_1
{
strings:
	$a0 = { 8bec0e1fbc3400fcad86c48944fe444481fc0003f272 }


condition:
	$a0
}