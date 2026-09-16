rule Win_Trojan_Replicator_6
{
strings:
	$a0 = { 03b440cd21b8004231d231c9cd215a58813e53034d5a }


condition:
	$a0
}