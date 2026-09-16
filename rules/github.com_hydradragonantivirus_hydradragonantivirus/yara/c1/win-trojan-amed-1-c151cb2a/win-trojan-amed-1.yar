rule Win_Trojan_Amed_1
{
strings:
	$a0 = { 501e062e803e3e001e7503e9180157bbf3008bcbbf28002e8a1601002e301547fec2e2f8 }


condition:
	$a0
}