rule Win_Trojan_Mayberry_13
{
strings:
	$a0 = { 023b16fa02744a81c2f6028916f702baf902cd21b440b9f30290ba0600cd2132c0 }


condition:
	$a0
}