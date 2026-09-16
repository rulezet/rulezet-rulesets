rule Win_Trojan_Letter_H_1
{
strings:
	$a0 = { e1009c5150521e80fc4b7405e99e002000538bda43803f0075fa807fff4d750a807ffa4e74045beb08905bba45 }


condition:
	$a0
}