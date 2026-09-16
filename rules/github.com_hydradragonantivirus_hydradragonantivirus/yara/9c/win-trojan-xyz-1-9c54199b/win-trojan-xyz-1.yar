rule Win_Trojan_XYZ_1
{
strings:
	$a0 = { 0143515033c9cd21b8413de85e00b8005750cd215152b440ba8903b90002cd21 }


condition:
	$a0
}