rule Win_Trojan_Leathal_1
{
strings:
	$a0 = { 4233c933d2cd21b80040b90a025783ef068bd7cd215fb80040b9c8005781c7fa008bd7cd215f }


condition:
	$a0
}