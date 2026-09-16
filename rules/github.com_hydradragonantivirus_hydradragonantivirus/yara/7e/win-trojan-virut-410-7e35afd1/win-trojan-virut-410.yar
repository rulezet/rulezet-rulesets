rule Win_Trojan_Virut_410
{
strings:
	$a0 = { e801000000fc608bdce9bbc0ffff8bf68d1404fc518d368d12fc50e9d5bdffffc3f5fc9ec45e8ac0b94c3d }


condition:
	$a0
}