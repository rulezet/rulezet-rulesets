rule Win_Trojan_WarCannibal_1
{
strings:
	$a0 = { b9ee00ba0001cd21b801572e8b0e96002e8b169800cd }


condition:
	$a0
}