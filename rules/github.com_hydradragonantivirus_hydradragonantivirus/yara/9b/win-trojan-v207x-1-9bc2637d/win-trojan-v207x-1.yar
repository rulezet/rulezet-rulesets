rule Win_Trojan_V207X_1
{
strings:
	$a0 = { 81ee0301501e068cc88ed80633c08ec026a19a00073d0010 }


condition:
	$a0
}