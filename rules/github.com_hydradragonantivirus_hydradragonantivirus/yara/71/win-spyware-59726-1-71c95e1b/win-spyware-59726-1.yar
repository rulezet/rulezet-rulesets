rule Win_Spyware_59726_1
{
strings:
	$a0 = { 558bec81c4d8feffff60837d0c010f8571 }

	$a1 = { 504f53545f55524c31 }

	$a2 = { 534f554c }


condition:
	$a0 and $a1 and $a2
}