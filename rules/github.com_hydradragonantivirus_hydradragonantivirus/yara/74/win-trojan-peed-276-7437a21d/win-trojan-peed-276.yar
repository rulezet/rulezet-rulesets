rule Win_Trojan_Peed_276
{
strings:
	$a0 = { 89fb682a25ff005ee843000000681c1600005981c1b011000081c11c160000ba }


condition:
	$a0
}