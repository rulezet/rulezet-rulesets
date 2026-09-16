rule Win_Trojan_ErrorInc_1
{
strings:
	$a0 = { 0203d5b90700b440cd2133c933d2b80242cd21e830008bd581c20701b90401b440cd21e82000 }


condition:
	$a0
}