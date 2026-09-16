rule Win_Trojan_Grum_2
{
strings:
	$a0 = { 486c4a06137f79ea922a26028028 }


condition:
	$a0
}