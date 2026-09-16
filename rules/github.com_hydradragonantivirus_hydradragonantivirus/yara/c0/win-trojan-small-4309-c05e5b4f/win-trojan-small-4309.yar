rule Win_Trojan_Small_4309
{
strings:
	$a0 = { e8??000000e8??0000008d2d96812700e8??00000092 }


condition:
	$a0
}