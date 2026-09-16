rule Win_Trojan_SubSeven_14
{
strings:
	$a0 = { aabe5df4f24bdb67a4fa129fe824201cc65a6d0240cbb6d94a0d340a871597071facd766e212b7b83300e5504551728c984e0ea68ac96e2eba6588d90a9dd73b }


condition:
	$a0
}