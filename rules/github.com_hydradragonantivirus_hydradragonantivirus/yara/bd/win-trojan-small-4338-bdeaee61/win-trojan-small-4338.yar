rule Win_Trojan_Small_4338
{
strings:
	$a0 = { 68a0304000e815fdffff83c40485c07419506a006801041000ffd78be86a0155ffd66a0055ffd655ffd3 }


condition:
	$a0
}