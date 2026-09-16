rule Win_Trojan_Quarinetine_1
{
strings:
	$a0 = { 21c606c00100b8014cbac30381c20104cd21b8014ccd211e0e1f81366b03aee381367b03207981 }


condition:
	$a0
}