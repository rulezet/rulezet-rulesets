rule Win_Trojan_Silly_37
{
strings:
	$a0 = { b43fcd21055d00803dbb74e35033c9b8004299cd2159b601b440cd21061fcb }


condition:
	$a0
}