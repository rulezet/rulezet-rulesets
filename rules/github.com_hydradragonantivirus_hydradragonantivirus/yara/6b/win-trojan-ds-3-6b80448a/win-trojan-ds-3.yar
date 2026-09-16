rule Win_Trojan_DS_3
{
strings:
	$a0 = { 8ed3bc007c8ec4b80802b90500ba8000cd1372000668c300cb }


condition:
	$a0
}