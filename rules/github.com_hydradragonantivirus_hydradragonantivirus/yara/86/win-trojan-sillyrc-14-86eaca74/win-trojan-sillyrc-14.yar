rule Win_Trojan_SillyRC_14
{
strings:
	$a0 = { f077232d0300a3d101b440b9e000ba0001cd21b8004233c933d2cd21b440bad001b90400cd21 }


condition:
	$a0
}