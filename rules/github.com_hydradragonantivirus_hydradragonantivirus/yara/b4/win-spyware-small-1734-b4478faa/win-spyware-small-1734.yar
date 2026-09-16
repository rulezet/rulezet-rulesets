rule Win_Spyware_Small_1734
{
strings:
	$a0 = { 8d8594feffff50575768000000085757575657ff1504714000 }


condition:
	$a0
}