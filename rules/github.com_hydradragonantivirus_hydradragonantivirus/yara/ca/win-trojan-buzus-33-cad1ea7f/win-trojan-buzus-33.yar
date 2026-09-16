rule Win_Trojan_Buzus_33
{
strings:
	$a0 = { 5589e583ec146a02ff1504824100e8fdfeffff8db6000000008dbc27000000005589e5 }


condition:
	$a0
}