rule Win_Trojan_Baba_5
{
strings:
	$a0 = { a17901402ea37901582d03002ea367012e803e65010f74208cc88ed8b44033d2b97b01cd2133c9 }


condition:
	$a0
}