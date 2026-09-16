rule Win_Trojan_EncePhalyt_1
{
strings:
	$a0 = { 13b1a8be80028bfbf3a4b8010341cd13beae7d83c610381475f98b148b4c02b80102cd13ffe383 }


condition:
	$a0
}