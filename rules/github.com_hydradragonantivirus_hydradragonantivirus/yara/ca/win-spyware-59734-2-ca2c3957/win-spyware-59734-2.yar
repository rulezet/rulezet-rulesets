rule Win_Spyware_59734_2
{
strings:
	$a0 = { 558bec81c48cfeffff60837d0c010f851403 }

	$a1 = { 504f53545f55524c31 }

	$a2 = { 4858484b5342005f4e414d45 }


condition:
	$a0 and $a1 and $a2
}