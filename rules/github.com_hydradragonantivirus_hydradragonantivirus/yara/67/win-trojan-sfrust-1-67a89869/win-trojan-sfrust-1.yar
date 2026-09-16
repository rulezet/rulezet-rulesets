rule Win_Trojan_Sfrust_1
{
strings:
	$a0 = { f91e74de3e8abe090380e70180ff01750eb443b0 }


condition:
	$a0
}