rule Win_Trojan_Warsaw_1
{
strings:
	$a0 = { 8cc0408ec08bfb33c9268a2580fc2e740a474183f90c }


condition:
	$a0
}