rule Win_Trojan_VGEN_414
{
strings:
	$a0 = { 550280ee05b426cd218b6d2cb44abb8900cd21b452cd21268b5ffe8cc8488cd98edb438bd3035d030bed75233b }


condition:
	$a0
}