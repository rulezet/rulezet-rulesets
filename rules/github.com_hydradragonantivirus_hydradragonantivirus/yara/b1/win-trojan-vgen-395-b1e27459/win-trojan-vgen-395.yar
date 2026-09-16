rule Win_Trojan_VGEN_395
{
strings:
	$a0 = { cb1881c2721c81c2133781eac20981ea7b2881ea1e1981c2c93081eaf50d81ea572e81c2241c81c26e3781ea810981 }


condition:
	$a0
}