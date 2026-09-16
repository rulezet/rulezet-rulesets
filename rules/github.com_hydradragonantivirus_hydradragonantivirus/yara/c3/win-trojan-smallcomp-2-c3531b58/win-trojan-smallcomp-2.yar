rule Win_Trojan_SmallComp_2
{
strings:
	$a0 = { fc4b75475653515706501e52bf6901578bf20e07acaa0a }


condition:
	$a0
}