rule Win_Trojan_Deltree_30
{
strings:
	$a0 = { 6563686f206f666640205c6364202a2e2a2064656c74726565205c79 }


condition:
	$a0
}