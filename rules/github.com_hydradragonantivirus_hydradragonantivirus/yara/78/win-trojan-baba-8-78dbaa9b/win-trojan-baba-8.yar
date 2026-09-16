rule Win_Trojan_Baba_8
{
strings:
	$a0 = { 77732d03002ea38a022e803e88020f74648cc88ed8b44033d2b99e02cd2133c933d2b80042 }


condition:
	$a0
}