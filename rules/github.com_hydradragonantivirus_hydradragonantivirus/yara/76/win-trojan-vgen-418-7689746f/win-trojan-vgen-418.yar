rule Win_Trojan_VGEN_418
{
strings:
	$a0 = { 525657551e069cfce800005e83ee0e8bec8b46142d03008946145033ff8ec726c43ee40183ef62b80312cd2f8c }


condition:
	$a0
}