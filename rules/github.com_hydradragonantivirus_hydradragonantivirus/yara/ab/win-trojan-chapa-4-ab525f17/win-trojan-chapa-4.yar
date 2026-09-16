rule Win_Trojan_Chapa_4
{
strings:
	$a0 = { 4d5a742b817c014b4d7424e87effb440b9c2010e1fba00020ee857ffe879ffb440b9c201ba00bf }


condition:
	$a0
}