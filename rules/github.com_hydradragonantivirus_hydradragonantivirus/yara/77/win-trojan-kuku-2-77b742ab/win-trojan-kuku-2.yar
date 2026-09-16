rule Win_Trojan_Kuku_2
{
strings:
	$a0 = { 05c001a30101b9c0015ab440cd217231 }


condition:
	$a0
}