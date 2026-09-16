rule Win_Trojan_Belirs_1
{
strings:
	$a0 = { 803e340290742232c0e83c00b440b904000e1fba2b02cd21b002e82b00b440b963010e1fba0001 }


condition:
	$a0
}