rule Win_Trojan_SW_2
{
strings:
	$a0 = { 1fbf1901033e0301b90700ff3583ef02e2f9bffe00b94000ff3583ef02e2f9e849ffe824ffb44eb92000ba0701f8cd }


condition:
	$a0
}