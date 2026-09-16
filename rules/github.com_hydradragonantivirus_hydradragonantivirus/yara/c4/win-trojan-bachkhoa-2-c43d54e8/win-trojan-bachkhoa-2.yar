rule Win_Trojan_BachKhoa_2
{
strings:
	$a0 = { e983e9102e310783c302e2f8c32ea3680f2e891e }


condition:
	$a0
}