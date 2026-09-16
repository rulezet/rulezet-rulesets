rule Win_Trojan_Bad_2
{
strings:
	$a0 = { ebd9b42acd213c017411eb1d9007 }


condition:
	$a0
}