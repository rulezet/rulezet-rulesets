rule Win_Trojan_FLV_1
{
strings:
	$a0 = { 5250579a0e002f0183c408ff7608ff7606ff76f0ff76ee9a09003f0183c4081eb8860050ff }


condition:
	$a0
}