rule Win_Trojan_Plastique_3
{
strings:
	$a0 = { 2305b82125cd218e064300268e062c }


condition:
	$a0
}