rule Win_Trojan_Ear_6
{
strings:
	$a0 = { 01b91e022e81371e0483c302e2f6 }


condition:
	$a0
}