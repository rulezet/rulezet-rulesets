rule Win_Trojan_Suleiman_2
{
strings:
	$a0 = { dab1cd213ddada746cb82135cd218c060601891e0401b80158bb0200cd21b80358bb0100cd21b4 }


condition:
	$a0
}