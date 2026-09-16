rule Win_Trojan_Peed_290
{
strings:
	$a0 = { bace09ffffff7500e84e00000068d4b200005981c1d817000081e964c4ffff81 }


condition:
	$a0
}