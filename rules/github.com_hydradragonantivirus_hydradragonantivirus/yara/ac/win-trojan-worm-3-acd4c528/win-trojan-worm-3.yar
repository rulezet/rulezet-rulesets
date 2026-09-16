rule Win_Trojan_Worm_3
{
strings:
	$a0 = { 70617373 }

	$a1 = { 6170706c69636174696f6e2f6f637465742d73747265616d3b }

	$a2 = { 6e616d653d22 }

	$a3 = { 2e7a6970220a }

	$a4 = { 0a5545734442416f414151414141 }

	$a5 = { 414141414141414141 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5
}