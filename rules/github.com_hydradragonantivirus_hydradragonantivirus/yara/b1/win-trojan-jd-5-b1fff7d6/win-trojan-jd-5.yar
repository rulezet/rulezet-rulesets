rule Win_Trojan_JD_5
{
strings:
	$a0 = { 57cd215152ba0001b9a701b440cd21 }


condition:
	$a0
}