rule Win_Trojan_Coconut_6
{
strings:
	$a0 = { 2c017705b8004ccd21b0ad5d81ed03011e060e0e071f8db60609b904008dbefe08f3a5e664 }


condition:
	$a0
}