rule Win_Trojan_5_1
{
strings:
	$a0 = { 1e0680fc4c741880fc4b7413071f5f5e5a595b582e }


condition:
	$a0
}