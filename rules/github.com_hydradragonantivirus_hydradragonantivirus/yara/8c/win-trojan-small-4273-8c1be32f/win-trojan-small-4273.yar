rule Win_Trojan_Small_4273
{
strings:
	$a0 = { 6a00e8??000000[0-10]565805dc090000505f[0-255]c355545db89d3f2200 }


condition:
	$a0
}