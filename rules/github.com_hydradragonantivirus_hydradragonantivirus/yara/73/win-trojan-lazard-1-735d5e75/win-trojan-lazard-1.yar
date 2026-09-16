rule Win_Trojan_Lazard_1
{
strings:
	$a0 = { 0160e8000000005d81ed0b204000e8110300008dbdf7234000ba11 }


condition:
	$a0
}