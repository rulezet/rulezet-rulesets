rule Win_Trojan_Find_2
{
strings:
	$a0 = { 5e83ee0306060e1fb199b499cd21e33bbd40001fa102002bc5a30200508cd848501f292e03000e1fb82135cd21 }


condition:
	$a0
}