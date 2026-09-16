rule Win_Trojan_VOLGA_1
{
strings:
	$a0 = { 53511e560e1fb455be0000b9000281feb1017203be000032242630274643e2eefec875e25e1f }


condition:
	$a0
}