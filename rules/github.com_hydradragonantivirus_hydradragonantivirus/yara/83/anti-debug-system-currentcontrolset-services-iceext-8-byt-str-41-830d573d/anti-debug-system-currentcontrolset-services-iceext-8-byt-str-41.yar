rule anti_debug__SYSTEM__CurrentControlSet__Services__IceExt__8_byt_STR_41_
{
strings:
	$a0 = { 53595354454d5c43757272656e74436f6e74726f6c5365745c53657276696365735c49636545787400 }

condition:
	$a0
}