rule Win_Trojan_Drepo_2
{
strings:
	$a0 = { e867098ccb438dc3f98dd3f888f682c5a50abca50a0d1c8807258a064c4d82fc39037af025c405d4043903 }


condition:
	$a0
}