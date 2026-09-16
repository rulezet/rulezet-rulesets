rule Win_Trojan_Agent_35875
{
strings:
	$a0 = { 558bec83ec286894ba1013ff15344110138985e8ffffffff15484110138985e4ffffffff1508411013 }


condition:
	$a0
}