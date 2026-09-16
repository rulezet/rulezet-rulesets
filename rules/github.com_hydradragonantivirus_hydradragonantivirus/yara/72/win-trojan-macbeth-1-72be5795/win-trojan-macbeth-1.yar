rule Win_Trojan_Macbeth_1
{
strings:
	$a0 = { 51b101b600b2801e07bb0000b403cd1389ec5dc3052a2e434f4d052a2e4558459a0000 }


condition:
	$a0
}