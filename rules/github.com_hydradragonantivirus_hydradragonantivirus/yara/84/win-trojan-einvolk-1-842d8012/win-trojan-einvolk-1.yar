rule Win_Trojan_Einvolk_1
{
strings:
	$a0 = { 02cd211fb43bbaab0203d6cd21b42acd2180fe0b7521b500b80d05b101ba8000cd13fec5 }


condition:
	$a0
}