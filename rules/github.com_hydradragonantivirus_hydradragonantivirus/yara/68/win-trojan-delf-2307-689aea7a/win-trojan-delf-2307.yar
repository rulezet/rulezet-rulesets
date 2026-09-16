rule Win_Trojan_Delf_2307
{
strings:
	$a0 = { 6669726577[0-40]5c7379736d6f642e657865 }

	$a1 = { 636d64202f6b204d4420433a5c6461656d6f6e }

	$a2 = { 5c6b6f646e6b776e762e737973 }

	$a3 = { 74656d5c6f75746c6f6b2e657865 }


condition:
	$a0 and $a1 and $a2 and $a3
}