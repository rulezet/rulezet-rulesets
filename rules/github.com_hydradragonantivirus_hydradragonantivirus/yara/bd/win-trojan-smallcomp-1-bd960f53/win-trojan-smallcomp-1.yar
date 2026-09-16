rule Win_Trojan_SmallComp_1
{
strings:
	$a0 = { 4b75465653515706501e52bf6801578bf20e07acaa0a }


condition:
	$a0
}