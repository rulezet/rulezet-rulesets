rule Win_Trojan_Delf_480
{
strings:
	$a0 = { 33c05568cb1d4b0064ff306489208b45fcbae41d4b00e8a122f5ffb800000100e8f76ef5ff }


condition:
	$a0
}