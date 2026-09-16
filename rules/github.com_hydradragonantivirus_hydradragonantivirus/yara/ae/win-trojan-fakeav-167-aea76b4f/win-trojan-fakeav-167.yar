rule Win_Trojan_FakeAV_167
{
strings:
	$a0 = { 5781ec000200008bfc6a7857e8????00008d577c33c951515152515703f8b85c6d6369abb861766933abb8322e646cab }


condition:
	$a0
}