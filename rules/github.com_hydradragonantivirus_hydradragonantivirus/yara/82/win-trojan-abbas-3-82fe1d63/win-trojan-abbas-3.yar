rule Win_Trojan_Abbas_3
{
strings:
	$a0 = { 4b75612e8c1ec5012e8916c70132c0e8b9022e890ec9 }


condition:
	$a0
}