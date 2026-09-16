rule Win_Trojan_Jain_2
{
strings:
	$a0 = { 028916ce02b002e84c00b440b9be06ba0000e86c017210b000e83a00b440b91800bacc02e8 }


condition:
	$a0
}