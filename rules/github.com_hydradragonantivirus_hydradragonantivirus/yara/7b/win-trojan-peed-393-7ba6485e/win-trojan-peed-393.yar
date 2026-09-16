rule Win_Trojan_Peed_393
{
strings:
	$a0 = { eb2c68b0b900006800??bfff5af7da595289e689d45889f405??????02526a016a016aff6a }


condition:
	$a0
}