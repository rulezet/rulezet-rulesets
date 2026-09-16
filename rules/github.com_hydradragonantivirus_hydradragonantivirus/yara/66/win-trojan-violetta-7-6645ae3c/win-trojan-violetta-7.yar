rule Win_Trojan_Violetta_7
{
strings:
	$a0 = { 25b0ff061f89dacd210e1fb425b021ba0003cdffb8f125 }


condition:
	$a0
}