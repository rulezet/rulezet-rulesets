rule Win_Trojan_Vgen_7
{
strings:
	$a0 = { 1373436566fe0246524f474749452e434f4d0000bbffffb44acd2181ebf01f7318ba2b01b90f00e979014f7574206f }


condition:
	$a0
}