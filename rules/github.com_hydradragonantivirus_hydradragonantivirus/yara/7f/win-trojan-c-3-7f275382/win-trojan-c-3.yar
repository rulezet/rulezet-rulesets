rule Win_Trojan_C_3
{
strings:
	$a0 = { bb007eb901000e0e071f9c0ee820007217be0b7ebf0b7cb133f3a4b80103bb007cb1019c0ee8 }


condition:
	$a0
}