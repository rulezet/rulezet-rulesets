rule Win_Trojan_TaiPan_1
{
strings:
	$a0 = { 5e83ee03b8ce7bcd213dce7b75170e1f81c6a801bfa801b90a00fcf3a4061f06b8760050cb }


condition:
	$a0
}