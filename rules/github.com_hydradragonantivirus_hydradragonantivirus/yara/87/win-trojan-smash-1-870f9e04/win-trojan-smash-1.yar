rule Win_Trojan_Smash_1
{
strings:
	$a0 = { 4fba0801ebf2ba6a01b43bcd21b42fcd218c06a201891ea401cd21ba7701b41acd21b90700ba04 }


condition:
	$a0
}