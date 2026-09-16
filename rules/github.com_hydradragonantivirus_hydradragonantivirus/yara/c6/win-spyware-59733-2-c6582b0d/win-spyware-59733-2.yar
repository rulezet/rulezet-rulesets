rule Win_Spyware_59733_2
{
strings:
	$a0 = { 558bec81c4e4feffff60837d0c010f85d2 }

	$a1 = { 504f53545f55524c31 }

	$a2 = { 484b4252424f005f4e414d45 }


condition:
	$a0 and $a1 and $a2
}