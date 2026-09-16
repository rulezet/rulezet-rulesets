rule Win_Trojan_Antitrace_1
{
strings:
	$a0 = { b82135cd218c062f01891e2d01ba1901b425cd21ba3101cd271e5633f68edec57404ff34c704ebfe8f045e1fea }


condition:
	$a0
}