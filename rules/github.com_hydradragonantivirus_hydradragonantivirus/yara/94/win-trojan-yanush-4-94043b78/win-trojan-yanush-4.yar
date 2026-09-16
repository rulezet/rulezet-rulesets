rule Win_Trojan_Yanush_4
{
strings:
	$a0 = { f1fdb80040b9d6038d940501cd21e8f1fde8dffd }


condition:
	$a0
}