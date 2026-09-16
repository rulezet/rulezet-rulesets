rule anti_debug__kernel32_CloseHandle_and_NtClose__8_byt_20_
{
strings:
	$a0 = { 64ff3500000000648925000000006834120000e8 }

condition:
	$a0
}