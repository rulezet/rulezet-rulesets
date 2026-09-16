rule Win_Trojan_Gen_11
{
strings:
	$a0 = { 1701051801a30301b8004233c933d2cd21a188052d0600a3d104b440b90600bacd04cd21b80242 }


condition:
	$a0
}