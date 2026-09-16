rule Win_Trojan_Crypt_326
{
strings:
	$a0 = { b82bb33466488bc88bc84987d133d068429ef16b59505268bf7db02450e861cafeffc353a499 }


condition:
	$a0
}