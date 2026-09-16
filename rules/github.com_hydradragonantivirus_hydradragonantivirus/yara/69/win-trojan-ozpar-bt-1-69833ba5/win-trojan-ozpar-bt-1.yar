rule Win_Trojan_OZPAR_BT_1
{
strings:
	$a0 = { bc0002b9fe00f3a432f6b801ffbb000241cd13eb11b6018a4f2d80f907750232f6b801fecd131f }


condition:
	$a0
}