rule Win_Trojan_Klepavka_1
{
strings:
	$a0 = { cfc6066b04e990880e6c04882e6d04b440b90300ba6b04cd21b43ecd21b801438bceba7104cd21 }


condition:
	$a0
}