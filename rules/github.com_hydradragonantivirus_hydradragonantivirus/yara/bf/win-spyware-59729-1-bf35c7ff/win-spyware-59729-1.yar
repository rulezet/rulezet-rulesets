rule Win_Spyware_59729_1
{
strings:
	$a0 = { 558bec81c4d0feffff60837d0c }

	$a1 = { 504f53545f55524c31 }

	$a2 = { 42424652425342 }


condition:
	$a0 and $a1 and $a2
}