rule Win_Trojan_B_11
{
strings:
	$a0 = { 8000cd1372dfa189023906890074d6e865ffb8010331db41cd13ebc9bebe01b90400 }


condition:
	$a0
}