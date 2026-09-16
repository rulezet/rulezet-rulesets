rule Win_Trojan_Vundo_486
{
strings:
	$a0 = { 5053e91dfeffff83eb0185c0e9bafaffff00000000e8bbfeffffe836ffffff58 }


condition:
	$a0
}