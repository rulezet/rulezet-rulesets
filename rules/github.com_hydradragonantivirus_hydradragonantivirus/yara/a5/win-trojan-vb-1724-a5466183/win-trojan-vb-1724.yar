rule Win_Trojan_VB_1724
{
strings:
	$a0 = { 6a76647a003034367d23322e00000000010000005855 }


condition:
	$a0
}