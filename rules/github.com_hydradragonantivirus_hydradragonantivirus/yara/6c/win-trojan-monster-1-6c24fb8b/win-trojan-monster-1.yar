rule Win_Trojan_Monster_1
{
strings:
	$a0 = { b43c33c9ba7502cd21b440b9d500ba0001cd215a59b80157cd2159e81d00b41aba8000cd21 }


condition:
	$a0
}