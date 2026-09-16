rule Win_Trojan_VGEN_209
{
strings:
	$a0 = { 08bb8808c1eb044343b44acd21b409ba0902cd21fcbe8000bf3e03ac4633c988c10bc9750bb409ba6002cd21b44c }


condition:
	$a0
}