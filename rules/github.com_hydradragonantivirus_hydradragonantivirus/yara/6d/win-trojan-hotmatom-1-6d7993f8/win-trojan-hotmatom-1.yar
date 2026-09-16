rule Win_Trojan_Hotmatom_1
{
strings:
	$a0 = { c745fc03000000c745985c704100c74590080000008d55908d4da0ff151c114000 }


condition:
	$a0
}