rule Win_Trojan_Vundo_40
{
strings:
	$a0 = { 60e8531900002eac023000000172 }


condition:
	$a0
}