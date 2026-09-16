rule Win_Trojan_Crypt_191
{
strings:
	$a0 = { 52ba4208222081c2c865704d03da5a56be0240aa0481c6082ee8682bde5e5058535383c404565683 }


condition:
	$a0
}