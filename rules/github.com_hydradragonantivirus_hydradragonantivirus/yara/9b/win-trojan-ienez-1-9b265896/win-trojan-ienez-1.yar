rule Win_Trojan_Ienez_1
{
strings:
	$a0 = { 0c02eee80400e95905e2b96d05902e8a26130033ff3065279047e2f9c3 }


condition:
	$a0
}