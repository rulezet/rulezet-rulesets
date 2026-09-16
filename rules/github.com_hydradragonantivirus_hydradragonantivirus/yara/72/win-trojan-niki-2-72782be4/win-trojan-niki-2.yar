rule Win_Trojan_Niki_2
{
strings:
	$a0 = { 6f726d617420633a2f712f753e6e756c5589e581ec00019a7d02b0008dbe00ff1657bff4090e57 }


condition:
	$a0
}