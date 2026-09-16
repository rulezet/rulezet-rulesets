rule Win_Trojan_Emmie_1
{
strings:
	$a0 = { cefacd213dface750883fb0c7d1fe818ffb8002ccd13b8a5ffb9cccccd16 }


condition:
	$a0
}