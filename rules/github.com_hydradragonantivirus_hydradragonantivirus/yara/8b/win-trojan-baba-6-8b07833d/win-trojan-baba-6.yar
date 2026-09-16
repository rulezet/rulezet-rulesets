rule Win_Trojan_Baba_6
{
strings:
	$a0 = { 7c633d00fa775e2d03002ea39a012e803e98010f744f8cc88ed8b44033d2b9ad01cd2133c9 }


condition:
	$a0
}