rule Win_Trojan_Vundo_451
{
strings:
	$a0 = { e9ec03000000000000556690d3cdbd38130d0221dd8bec83e4f86687c983 }

	$a1 = { 6a6a696e6460626469636b }


condition:
	$a0 and $a1
}