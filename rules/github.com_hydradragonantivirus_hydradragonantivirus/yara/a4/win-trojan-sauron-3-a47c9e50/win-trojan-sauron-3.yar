rule Win_Trojan_Sauron_3
{
strings:
	$a0 = { 1fb430cd21b8f302e800005e2bf080fb01750f8cc00510002e018428002effac26002e80bc2a00017503e989008cc0 }


condition:
	$a0
}