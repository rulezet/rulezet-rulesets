rule Win_Trojan_IMI_1
{
strings:
	$a0 = { 1e6d0033d29c2eff1e6f000e1fa37b00b8004233c99cff1e6f00b44033d2b900069cff1e6f00 }


condition:
	$a0
}