rule Win_Trojan_Autorun_402
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d636a316d2e636f6d }


condition:
	$a0
}