rule Win_Trojan_VGEN_701
{
strings:
	$a0 = { 08b9e53782c5d0b00a2e0005d2c847e2f889fb81ebfc079148fce82905e90000cd210ac474611e8bcb8cdfb413cd }


condition:
	$a0
}