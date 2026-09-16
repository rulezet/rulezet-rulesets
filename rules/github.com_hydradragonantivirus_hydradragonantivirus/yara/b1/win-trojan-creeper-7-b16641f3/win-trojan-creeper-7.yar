rule Win_Trojan_Creeper_7
{
strings:
	$a0 = { 77293ddc0272240500018984affeb440b9dc018bd6cd21b80042 }


condition:
	$a0
}