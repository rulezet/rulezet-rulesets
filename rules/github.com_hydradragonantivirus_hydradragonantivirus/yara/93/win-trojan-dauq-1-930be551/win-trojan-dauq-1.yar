rule Win_Trojan_Dauq_1
{
strings:
	$a0 = { fc5dbf0601552bef03fd572e8c9ecb065e0e0eb94c00071fac3416aae2fa }


condition:
	$a0
}