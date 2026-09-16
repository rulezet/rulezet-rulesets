rule Win_Trojan_Mudshark_1
{
strings:
	$a0 = { a902b2e98896a8028d960301b93801b440cd2133c9b8004299cd21b903008d96a802b440cd21 }


condition:
	$a0
}