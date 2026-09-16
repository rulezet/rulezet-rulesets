rule Win_Trojan_LamDie_1
{
strings:
	$a0 = { bf0002be2201a481fe2e017402ebf781ffff047f02ebec90b002bb0002b91000ba0000cd2642ebfb }


condition:
	$a0
}