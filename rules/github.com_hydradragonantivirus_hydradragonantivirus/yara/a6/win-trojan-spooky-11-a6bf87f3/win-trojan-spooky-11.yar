rule Win_Trojan_Spooky_11
{
strings:
	$a0 = { ed0301b8addecd2181fbadde754c2e8c9e4f022e8c8651020e0e1f072e8dbe57012e8db65302b90400f3a52e8b86 }


condition:
	$a0
}