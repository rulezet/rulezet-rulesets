rule Win_Trojan_Quinine_1
{
strings:
	$a0 = { 6800b90002f7e103066600055701730142f7f1a3680089166600b95701ba0000b440cd21c3 }


condition:
	$a0
}