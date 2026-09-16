rule Win_Trojan_Icelandic_2
{
strings:
	$a0 = { 81fa180c75062ec606200101e919 }


condition:
	$a0
}