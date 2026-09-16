rule Win_Trojan_Joker_4
{
strings:
	$a0 = { e842fd535533ede84dfd5d5be85a00b90b00ba1202b440e82bfd2e8b0e96002e8b169800 }


condition:
	$a0
}