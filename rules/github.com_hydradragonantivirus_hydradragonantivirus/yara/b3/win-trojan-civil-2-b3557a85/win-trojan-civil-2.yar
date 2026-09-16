rule Win_Trojan_Civil_2
{
strings:
	$a0 = { b90200b001bb007c2e8e061500b402cd13b280b600b90300b00cbb00002e8e061900b402cd13 }


condition:
	$a0
}