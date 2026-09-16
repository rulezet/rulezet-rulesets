rule Win_Trojan_Crypt_211
{
strings:
	$a0 = { 558becb8b0943c39bba8bf573750e800000000582da81a0000b96d1a0000ba211b0000be001000 }


condition:
	$a0
}