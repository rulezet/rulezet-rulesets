rule Win_Trojan_Digger_1
{
strings:
	$a0 = { 04001fa5a5c744fc40068c44feb9c201bb73069c9c5880cc01509de2fe }


condition:
	$a0
}