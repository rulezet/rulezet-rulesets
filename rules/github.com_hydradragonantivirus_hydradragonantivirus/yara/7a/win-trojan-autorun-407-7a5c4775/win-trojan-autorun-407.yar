rule Win_Trojan_Autorun_407
{
strings:
	$a0 = { 502bc056515253570f84bdffffffdc64b5c7ae14475ee96dfe }

	$a1 = { 6470312e666e65 }

	$a2 = { 7c4e495f27 }


condition:
	$a0 and $a1 and $a2
}