rule Win_Trojan_Popuper_2
{
strings:
	$a0 = { 706f70757065722e65786500506f70757065724d696e696d6f6e4576656e7400 }


condition:
	$a0
}