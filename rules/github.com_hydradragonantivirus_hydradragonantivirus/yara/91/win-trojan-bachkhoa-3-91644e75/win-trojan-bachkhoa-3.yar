rule Win_Trojan_BachKhoa_3
{
strings:
	$a0 = { 3106f010a11003c32e8f065b039c2eff1efa022eff365b03c3c50ab003cfb9fd03d1e983e9102e }


condition:
	$a0
}