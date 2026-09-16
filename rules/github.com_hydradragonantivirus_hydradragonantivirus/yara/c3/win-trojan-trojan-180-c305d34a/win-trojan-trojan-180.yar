rule Win_Trojan_Trojan_180
{
strings:
	$a0 = { ba9e00cd21b8014383c903cd21b44febe8 }


condition:
	$a0
}