rule Win_Trojan_Crypt_128
{
strings:
	$a0 = { 81e20000f0ff[0-10]81c2[0-70]8b0d[0-30]ffe0 }


condition:
	$a0
}