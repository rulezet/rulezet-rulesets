rule Win_Trojan_Ear_5
{
strings:
	$a0 = { 06b99d022e8137371683c302e2f6 }


condition:
	$a0
}