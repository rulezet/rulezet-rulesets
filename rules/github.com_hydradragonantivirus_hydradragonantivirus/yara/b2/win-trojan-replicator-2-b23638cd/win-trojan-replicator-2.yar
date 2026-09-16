rule Win_Trojan_Replicator_2
{
strings:
	$a0 = { 740d3d004b7503e842002eff2ec101b814ffcf0d0a }


condition:
	$a0
}