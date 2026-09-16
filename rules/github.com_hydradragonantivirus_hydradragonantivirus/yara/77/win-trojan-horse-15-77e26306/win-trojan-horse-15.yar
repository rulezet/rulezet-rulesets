rule Win_Trojan_Horse_15
{
strings:
	$a0 = { 8edfbb0301871e84002e899e8504 }


condition:
	$a0
}