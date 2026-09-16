rule Win_Trojan_Mango_1
{
strings:
	$a0 = { 03008986cf02b440b9d5018d960001cd21b8004233c933d2cd21b440b903008d96ce02cd21fe86 }


condition:
	$a0
}