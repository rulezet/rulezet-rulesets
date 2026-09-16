rule Win_Trojan_Sam_1
{
strings:
	$a0 = { ff01070055a600000300ffff43190000a2050000050000004319 }


condition:
	$a0
}