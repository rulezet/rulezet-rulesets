rule Win_Trojan_Spellbound_1
{
strings:
	$a0 = { 01e808feb802422e8b1ed60133c933d2cd21b4402e8b0ec9011e2e8e1ed101ba0000cd211fb8 }


condition:
	$a0
}