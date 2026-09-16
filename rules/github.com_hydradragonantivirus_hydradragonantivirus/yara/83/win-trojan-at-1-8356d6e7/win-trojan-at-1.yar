rule Win_Trojan_AT_1
{
strings:
	$a0 = { 428bcacd35b440b22db103892ccde5b43ecde51f61ea }


condition:
	$a0
}