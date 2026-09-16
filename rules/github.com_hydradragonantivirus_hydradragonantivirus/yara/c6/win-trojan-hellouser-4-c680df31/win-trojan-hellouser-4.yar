rule Win_Trojan_HelloUser_4
{
strings:
	$a0 = { 8db60501bfbcfcb91d02fcf3a4bed9fce846ffb440babcfcb91d02cd21b80042e84300b440b903 }


condition:
	$a0
}