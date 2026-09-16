rule Win_Trojan_Stinger_1
{
strings:
	$a0 = { 0c01eb2890c6460c008bd5b9c602908b5e2eb440cd21c6460c02eb1090e80000fab0ade664 }


condition:
	$a0
}