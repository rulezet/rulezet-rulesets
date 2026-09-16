rule Win_Trojan_Tiny_50
{
strings:
	$a0 = { 050301394401721b89444f895451ba2100b440cd21b800429989d1cd21b440b118cd21b43e }


condition:
	$a0
}