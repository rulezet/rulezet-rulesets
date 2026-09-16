rule Win_Trojan_WinStart_1
{
strings:
	$a0 = { 4543484f20204f46460d0a3a732572230d0a434f505920 }


condition:
	$a0
}