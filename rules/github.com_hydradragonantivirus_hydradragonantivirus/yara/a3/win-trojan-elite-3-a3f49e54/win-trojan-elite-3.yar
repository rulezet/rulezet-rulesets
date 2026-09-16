rule Win_Trojan_Elite_3
{
strings:
	$a0 = { a5a5b9d6008b56008b5efab440cd2133c98bd18b5efab80042cd218b5e00c646fce98b46e9 }


condition:
	$a0
}