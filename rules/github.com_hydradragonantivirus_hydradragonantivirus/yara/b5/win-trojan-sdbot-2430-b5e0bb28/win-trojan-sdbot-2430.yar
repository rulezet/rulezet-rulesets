rule Win_Trojan_SdBot_2430
{
strings:
	$a0 = { eb016451565e83ecfc83ec04e804000000 }


condition:
	$a0
}