rule Win_Trojan_DOS_3
{
strings:
	$a0 = { 89e581ec0202eb145b467269656e642d342c2044756b652f534d465d8dbe00ff165731c0509a58 }


condition:
	$a0
}