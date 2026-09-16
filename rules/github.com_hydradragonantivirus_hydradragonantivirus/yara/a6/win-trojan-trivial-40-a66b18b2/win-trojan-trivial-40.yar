rule Win_Trojan_Trivial_40
{
strings:
	$a0 = { 1aba3501cd21b44eba6001b92600cd21721eb441ba5301cd21b43cb90000ba5301cd21720bb96600ba000193b440cd21b44ccd21 }


condition:
	$a0
}