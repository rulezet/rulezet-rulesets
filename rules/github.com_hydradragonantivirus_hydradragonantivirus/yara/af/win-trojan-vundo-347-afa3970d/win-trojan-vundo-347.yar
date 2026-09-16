rule Win_Trojan_Vundo_347
{
strings:
	$a0 = { 6a0c6874120210e830ffffffe850ffffff33c0408945e433ff897dfc8b750c3bf70f8597fbffffc3 }


condition:
	$a0
}