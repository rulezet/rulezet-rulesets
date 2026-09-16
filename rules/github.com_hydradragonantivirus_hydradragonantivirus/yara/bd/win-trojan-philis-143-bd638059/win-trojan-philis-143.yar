rule Win_Trojan_Philis_143
{
strings:
	$a0 = { 56893c24515083c40453893c }


condition:
	$a0
}