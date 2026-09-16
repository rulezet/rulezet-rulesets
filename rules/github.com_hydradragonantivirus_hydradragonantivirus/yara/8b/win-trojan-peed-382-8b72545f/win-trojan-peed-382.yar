rule Win_Trojan_Peed_382
{
strings:
	$a0 = { 01f805412500003d412500000f849b0000003d21 }


condition:
	$a0
}