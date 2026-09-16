rule Win_Trojan_Self_2
{
strings:
	$a0 = { 0600b44ecd217303eb2c90ba3701 }


condition:
	$a0
}