rule Win_Trojan_Leprosy_39
{
strings:
	$a0 = { 02900090e80300e9ee00505b51bb40018a2f322e030190882f83c30181fb68047eee59c390 }


condition:
	$a0
}