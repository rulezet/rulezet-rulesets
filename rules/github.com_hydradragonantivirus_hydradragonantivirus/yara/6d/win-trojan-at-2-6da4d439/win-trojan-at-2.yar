rule Win_Trojan_AT_2
{
strings:
	$a0 = { 428bcacde5b440b22db103892ccde5b43ecde51f61ea }


condition:
	$a0
}