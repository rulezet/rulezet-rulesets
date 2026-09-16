rule Win_Trojan_Jerusalem_49
{
strings:
	$a0 = { cd21e800005e8bdeb99006902e8074171d46e2f881fb03007502eb36 }


condition:
	$a0
}