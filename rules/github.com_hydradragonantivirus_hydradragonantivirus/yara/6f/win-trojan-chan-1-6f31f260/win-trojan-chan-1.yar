rule Win_Trojan_Chan_1
{
strings:
	$a0 = { 33c08ed0bc007c1607bb78068d878afbba0000b9025016cd1372e453cb }


condition:
	$a0
}