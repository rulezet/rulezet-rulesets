rule Win_Trojan_Pif_1
{
strings:
	$a0 = { 5e83ee0350511e06b8fe4bcd2181ff000172478cd8488ec026a103002d }


condition:
	$a0
}