rule Win_Trojan_Crypt_136
{
strings:
	$a0 = { 6800????0058[0-50]8b4c2404[0-70]b900f0ffff[0-35]8b940a1410fe7f[0-20]b90000ef01[0-40]8b8c191410fe7f[0-40]cd01 }


condition:
	$a0
}