rule Win_Trojan_Trojan_74
{
strings:
	$a0 = { 9bf8ccfcf80becbade6f04e6fcd7bb8dcb35cb3290eb0314b740cc3e0194 }


condition:
	$a0
}