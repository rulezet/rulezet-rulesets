rule Win_Trojan_SillyC_116
{
strings:
	$a0 = { 40bad00103d5b90400cd21b8024233c933d2cd21b440ba000103d5b9e20181e90001cd21b43ecd }


condition:
	$a0
}