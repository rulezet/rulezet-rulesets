rule Win_Trojan_Anthrax_2
{
strings:
	$a0 = { 1358b101bb0004cd130e1fbe9b038bfb }


condition:
	$a0
}