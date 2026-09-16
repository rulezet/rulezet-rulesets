rule Win_Trojan_Tiny_8
{
strings:
	$a0 = { 03b43fb9a1008bd6cc2bc8752ab8024299cca31c02b440803c4d750a39540675163864187411 }


condition:
	$a0
}