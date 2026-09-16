rule Win_Trojan_Trivial_448
{
strings:
	$a0 = { 40b9ef0181e90001ba0001cd21b43ecd214783ff0f75cd }


condition:
	$a0
}