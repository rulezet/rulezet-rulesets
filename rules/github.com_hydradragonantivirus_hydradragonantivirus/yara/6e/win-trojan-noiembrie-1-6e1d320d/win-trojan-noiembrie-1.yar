rule Win_Trojan_Noiembrie_1
{
strings:
	$a0 = { 03bd00f403df81eb050103f78a272aa4fbfe8827886600454356be340203f73bde5e75e8c3 }


condition:
	$a0
}