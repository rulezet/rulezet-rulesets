rule Win_Trojan_Sunset_2
{
strings:
	$a0 = { cd218beb066a000726c606ac03ea8bc383c32d051c0426a3ad03268c0eaf0307536a0068ac }


condition:
	$a0
}