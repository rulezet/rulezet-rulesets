rule Win_Trojan_Day31_1
{
strings:
	$a0 = { 8ed2bc007c68006007bb0001b90150b80302cd1372f9ea00010060 }


condition:
	$a0
}