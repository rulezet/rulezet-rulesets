rule Win_Trojan_Small_4121
{
strings:
	$a0 = { 505050505050ffd6c1e00881840500ffffff466343 }


condition:
	$a0
}