rule Win_Trojan_QKey_2
{
strings:
	$a0 = { e64132c0e6408ac4e640c3e8e6ffb435b009cd212e891e03012e8c060501b425b0090e1fba5001 }


condition:
	$a0
}