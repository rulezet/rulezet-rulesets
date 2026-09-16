rule Win_Spyware_4747_1
{
strings:
	$a0 = { 565303de5b50b852020522 }


condition:
	$a0
}