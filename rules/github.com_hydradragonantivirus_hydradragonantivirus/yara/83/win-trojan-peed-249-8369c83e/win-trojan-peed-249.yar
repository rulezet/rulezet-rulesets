rule Win_Trojan_Peed_249
{
strings:
	$a0 = { b8fb74b40b85fa93732a5589e551418b7d1066ab }


condition:
	$a0
}