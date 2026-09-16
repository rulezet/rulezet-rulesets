rule Win_Trojan_Argentina_3
{
strings:
	$a0 = { b42acd2181fa1905741581fa1406741581fa09077415 }


condition:
	$a0
}