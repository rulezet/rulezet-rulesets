rule Win_Trojan_Dikshev_35
{
strings:
	$a0 = { 9e00bf3f0157acaa3c2e75fabe3b01a5a55ab45bcd21720d93b440ba3f009087d1cd2187d1b44f }


condition:
	$a0
}