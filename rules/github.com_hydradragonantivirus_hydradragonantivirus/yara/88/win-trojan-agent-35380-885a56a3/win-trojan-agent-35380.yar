rule Win_Trojan_Agent_35380
{
strings:
	$a0 = { e9cc0d0400e927c20200e9926c0500e9ddbe0200e9a8990800e9 }

	$a1 = { 5c8545006775617264 }

	$a2 = { 005f4c6f636b00cc }


condition:
	$a0 and $a1 and $a2
}