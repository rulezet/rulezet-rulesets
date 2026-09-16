rule Win_Trojan_VLAD_18
{
strings:
	$a0 = { b440e8ca04721f909090baea0eb91c00b440e8ba04e8f900bae70eb90300b440e8ac04e832 }


condition:
	$a0
}