rule Win_Trojan_Small_4140
{
strings:
	$a0 = { e819000000ffe3ff150000000050ff5604816c0500c2ab233483c50345c38d1d }


condition:
	$a0
}