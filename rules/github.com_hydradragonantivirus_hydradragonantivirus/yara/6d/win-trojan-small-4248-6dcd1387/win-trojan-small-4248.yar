rule Win_Trojan_Small_4248
{
strings:
	$a0 = { eb00eb00eb00e800000000c70424b7704000eb00eb005850c371 }


condition:
	$a0
}