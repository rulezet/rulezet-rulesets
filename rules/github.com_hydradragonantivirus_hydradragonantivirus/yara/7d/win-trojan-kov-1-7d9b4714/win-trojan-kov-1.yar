rule Win_Trojan_KOV_1
{
strings:
	$a0 = { 06c606aa0100e8cb00e8f500b000e84901b440baf806b91a00cd212ec6066a07ffe960ffc6 }


condition:
	$a0
}