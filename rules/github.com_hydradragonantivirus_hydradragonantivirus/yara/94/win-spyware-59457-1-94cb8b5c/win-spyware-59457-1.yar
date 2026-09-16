rule Win_Spyware_59457_1
{
strings:
	$a0 = { 60be007040008dbe00a0ffff5783cdffeb1090 }

	$a1 = { 585054505357 }

	$a2 = { 5300650072007600650072002e006500780065 }


condition:
	$a0 and $a1 and $a2
}