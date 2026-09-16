rule Win_Trojan_ARCV_17
{
strings:
	$a0 = { 1701bd89fee2fe2e812c000046464575f6 }


condition:
	$a0
}