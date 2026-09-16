rule Win_Trojan__1495_0002_000_1
{
strings:
	$a0 = { 49015958b440b91303ba00019c2eff1e1901721db8004233c933d29c2eff1e1901720eba1d01 }


condition:
	$a0
}