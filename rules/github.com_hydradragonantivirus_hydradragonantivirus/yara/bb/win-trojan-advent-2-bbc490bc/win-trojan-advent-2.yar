rule Win_Trojan_Advent_2
{
strings:
	$a0 = { df8ec78ed78bfcbcca0afce80300e9 }


condition:
	$a0
}