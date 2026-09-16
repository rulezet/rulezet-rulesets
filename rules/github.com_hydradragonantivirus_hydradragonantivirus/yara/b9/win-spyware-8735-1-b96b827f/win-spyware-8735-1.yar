rule Win_Spyware_8735_1
{
strings:
	$a0 = { 535183c4040f02daeb008b1c2483c404e83a01000021b16568 }


condition:
	$a0
}