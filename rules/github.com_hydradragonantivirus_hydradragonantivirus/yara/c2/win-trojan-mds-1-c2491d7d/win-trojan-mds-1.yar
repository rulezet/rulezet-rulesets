rule Win_Trojan_MDS_1
{
strings:
	$a0 = { 030105dc00a34302b94b01ba0001b440cd217236b80042e85000b90400ba4202b440cd21 }


condition:
	$a0
}