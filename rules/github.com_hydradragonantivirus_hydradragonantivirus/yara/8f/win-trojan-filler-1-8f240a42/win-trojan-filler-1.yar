rule Win_Trojan_Filler_1
{
strings:
	$a0 = { 12bb4000f7e32d00108ec0ba0000eb }


condition:
	$a0
}