rule Win_Trojan_TaiPan_3
{
strings:
	$a0 = { e800005e83ee03b8ce7bcd213dce7b75170e1f81c6ac01bfac01b90a00fcf3a4061f06b8760050cb }


condition:
	$a0
}