rule Win_Trojan_Crypt_158
{
strings:
	$a0 = { 892c24e8(01|02|03|04)000000 }


condition:
	$a0
}