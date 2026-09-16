rule Win_Trojan_Yard_2
{
strings:
	$a0 = { 2ea31100b9e101ba1500b440e8ceff721733c933d2b80042e8c2ff720bb90500ba1000b440 }


condition:
	$a0
}