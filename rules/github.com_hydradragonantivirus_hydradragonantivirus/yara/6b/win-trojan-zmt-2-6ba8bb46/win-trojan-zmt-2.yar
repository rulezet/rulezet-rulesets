rule Win_Trojan_ZMT_2
{
strings:
	$a0 = { 43cd21b82135cd21895c4c908c444e908bd683c22b90 }


condition:
	$a0
}