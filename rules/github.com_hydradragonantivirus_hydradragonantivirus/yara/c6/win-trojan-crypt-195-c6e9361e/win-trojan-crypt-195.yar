rule Win_Trojan_Crypt_195
{
strings:
	$a0 = { 60f7dbb9d9a6bb0a0fabd30fbdf3f9684910400033c9c1c211baf240acc881d7342695 }

	$a1 = { f8512531506179a349 }


condition:
	$a0 and $a1
}