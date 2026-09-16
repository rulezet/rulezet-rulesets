rule Win_Trojan_Crypt_214
{
strings:
	$a0 = { 558becb8b39632c8bb7b60679b50e800000000582da81a0000b96d1a0000ba211b }


condition:
	$a0
}