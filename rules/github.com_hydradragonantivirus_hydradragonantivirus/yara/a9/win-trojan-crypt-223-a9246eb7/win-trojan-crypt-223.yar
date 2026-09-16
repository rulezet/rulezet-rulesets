rule Win_Trojan_Crypt_223
{
strings:
	$a0 = { eb043c50dbeb60578bfe031c245f53532b342483c4 }

	$a1 = { 75721b5e314e55434325 }


condition:
	$a0 and $a1
}