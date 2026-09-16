rule Win_Trojan_Kokos_1
{
strings:
	$a0 = { f00214b4acbb2b0100bba206a780610ff9446b0fb33805059ba4e733b20d41e10f00a00e4e86 }


condition:
	$a0
}