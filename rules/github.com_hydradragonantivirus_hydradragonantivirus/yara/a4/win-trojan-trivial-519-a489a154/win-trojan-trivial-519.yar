rule Win_Trojan_Trivial_519
{
strings:
	$a0 = { 018bdb9c7420998bcab80042cd21b000b457cd215152b440b97f00ba0001cd21b0015a59b4 }


condition:
	$a0
}