rule Win_Trojan_Weed_5
{
strings:
	$a0 = { 1358f00a0758f1d78d89eeebe259f700f94c5f59e8099da804f45ee2f1f8f1b10e82e3b1f827e8 }


condition:
	$a0
}