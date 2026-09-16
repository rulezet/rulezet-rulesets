rule Win_Trojan_Replicator_1
{
strings:
	$a0 = { 5d81ed03001e06b80463cd213bc374518cc0488ed8 }


condition:
	$a0
}