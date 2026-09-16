rule Win_Trojan_Manurave_1
{
strings:
	$a0 = { e45006b452cd218cc0073d00a0720da3ea00b44ebaed00e85b00730358cd21061fb8023db29ee8 }


condition:
	$a0
}