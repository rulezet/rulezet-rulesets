rule Win_Trojan_Prime_2
{
strings:
	$a0 = { e80300eb247f53bb2b01b94402512ea00701300743e2fb595b434b740ab44087f2cd2133dbeb }


condition:
	$a0
}