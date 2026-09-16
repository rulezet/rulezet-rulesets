rule Win_Trojan_Trivial_520
{
strings:
	$a0 = { 01cd21813e6d018bdb9c7420998bcab80042cd21b000b457cd215152b440b97f00ba0001cd21 }


condition:
	$a0
}