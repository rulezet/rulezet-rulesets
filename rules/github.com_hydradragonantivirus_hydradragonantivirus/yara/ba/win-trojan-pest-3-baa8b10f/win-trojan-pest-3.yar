rule Win_Trojan_Pest_3
{
strings:
	$a0 = { b100b600b202cd13b44ccd217400b802 }


condition:
	$a0
}