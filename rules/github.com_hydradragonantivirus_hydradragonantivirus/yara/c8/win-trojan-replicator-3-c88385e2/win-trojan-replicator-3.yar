rule Win_Trojan_Replicator_3
{
strings:
	$a0 = { 16cb02890ecd0231d2b9d801b440cd21b8004231d231c9 }


condition:
	$a0
}