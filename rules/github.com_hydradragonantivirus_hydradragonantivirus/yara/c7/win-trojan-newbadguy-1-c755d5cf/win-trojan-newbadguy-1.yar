rule Win_Trojan_NewBadGuy_1
{
strings:
	$a0 = { b90b1190b44ecd21907302eb2590ba9e00b8023d90cd21730390eb168bd890e84000ba800090b44fcd21907302eb0390ebdbb42acd21903c01740490eb }


condition:
	$a0
}