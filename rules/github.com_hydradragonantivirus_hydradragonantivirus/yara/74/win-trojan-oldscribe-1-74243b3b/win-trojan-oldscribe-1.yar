rule Win_Trojan_OldScribe_1
{
strings:
	$a0 = { 83ee0356fc81c65821bf0001a5a55e8d946121b41acd21e86a20b41aba8000cd21eb27900d2020200d0a2020fe2863 }


condition:
	$a0
}