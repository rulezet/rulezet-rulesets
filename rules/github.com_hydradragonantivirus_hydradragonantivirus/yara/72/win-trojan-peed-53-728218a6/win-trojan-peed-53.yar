rule Win_Trojan_Peed_53
{
strings:
	$a0 = { 8b6c241c83ed7883c51981c5fcfeffff83c0ff81eda000000085ed75 }


condition:
	$a0
}