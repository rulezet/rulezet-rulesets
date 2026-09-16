rule Win_Trojan_Riot_25
{
strings:
	$a0 = { 38018d964801cd21e81f00b80042b90000ba0000cd21b440b905008d96b601cd21fe86aa01 }


condition:
	$a0
}