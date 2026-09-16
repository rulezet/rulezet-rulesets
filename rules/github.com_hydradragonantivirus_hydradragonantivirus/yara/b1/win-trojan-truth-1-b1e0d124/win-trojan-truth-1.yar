rule Win_Trojan_Truth_1
{
strings:
	$a0 = { 0233d2592e8b1ef502b4409c2eff1ec0027218b801572e8b1ef5022e8b0ef3022e8b16f102 }


condition:
	$a0
}