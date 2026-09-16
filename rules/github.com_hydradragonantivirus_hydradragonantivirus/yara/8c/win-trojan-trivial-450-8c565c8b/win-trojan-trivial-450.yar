rule Win_Trojan_Trivial_450
{
strings:
	$a0 = { ba8201cd217271b42fcd21061f8d571eb80043cd215152b80143b90000cd21b8023dcd218bd8b80057cd21 }


condition:
	$a0
}