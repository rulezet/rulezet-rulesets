rule Win_Trojan_Trivial_487
{
strings:
	$a0 = { 04cd1a31c980fa017508b409ba6101cd21c3b42fcd2153b41aba9000cd21b44eba5a01b103cd217312b44fcd21730c }


condition:
	$a0
}