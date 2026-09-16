rule Win_Trojan_Crypt_194
{
strings:
	$a0 = { 6801604000e801000000c3c35f134785415f9b347270adb49f041f0af8cda7c29c5e3c8fff0383cd8724 }


condition:
	$a0
}