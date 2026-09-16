rule Win_Trojan_Replicator_4
{
strings:
	$a0 = { 02b440cd21b8004231d231c9cd215a58813eda024d5a }


condition:
	$a0
}