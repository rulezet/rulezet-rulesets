rule Win_Trojan_Kalisti_2
{
strings:
	$a0 = { 2d78585b204b616c6c697374202d20634834525f2070726573656e7473205d58782d }


condition:
	$a0
}