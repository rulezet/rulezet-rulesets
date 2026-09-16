rule Win_Trojan_BachKhoa_4
{
strings:
	$a0 = { 9033d9538bd583c4028bec83ed02314e0083ec028beac3 }


condition:
	$a0
}