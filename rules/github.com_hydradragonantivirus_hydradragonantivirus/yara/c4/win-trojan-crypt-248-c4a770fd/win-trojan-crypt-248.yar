rule Win_Trojan_Crypt_248
{
strings:
	$a0 = { 558bec83ec0c60b9edb6099381c765be91ffb9b575b30789d168 }


condition:
	$a0
}