rule Win_Trojan_IntMaster_1
{
strings:
	$a0 = { 5351525657551e069cfce800005e83ee0e8bec8b46142d03008946145033ff8ec726c43ee40183ef6290b80312cd2f }


condition:
	$a0
}