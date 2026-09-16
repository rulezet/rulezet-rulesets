rule Win_Trojan_TDSS_50
{
strings:
	$a0 = { 558bec83e4f881ecd40000005356578b7d088bc70faf450c6a0f33d259f7f18b75108d461f3bd0752268756507 }


condition:
	$a0
}