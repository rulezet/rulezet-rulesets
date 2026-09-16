rule Win_Trojan_Agent_35546
{
strings:
	$a0 = { 2e72756e20226f2e6c6e6b22 }

	$a1 = { 72756e28276f2e766273 }

	$a2 = { 773d2265222b6865782869292b[0-12]6d696428772c31322c3437 }


condition:
	$a0 and $a1 and $a2
}