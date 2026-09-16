rule Win_Trojan_Peed_30
{
strings:
	$a0 = { 1bb3d4dbed31e137d2e449607c3f48b7 }


condition:
	$a0
}