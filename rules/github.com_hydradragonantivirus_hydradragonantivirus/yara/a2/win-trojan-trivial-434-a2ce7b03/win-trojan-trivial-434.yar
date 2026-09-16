rule Win_Trojan_Trivial_434
{
strings:
	$a0 = { b92700ba1801cd217203e80700c32a2e434f4d00b42fcd218bf3c6069b0100817c1aa7007261b8003d8d541ecd21 }


condition:
	$a0
}