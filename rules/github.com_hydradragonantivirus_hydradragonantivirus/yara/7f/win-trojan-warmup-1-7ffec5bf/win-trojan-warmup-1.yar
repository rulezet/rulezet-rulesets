rule Win_Trojan_Warmup_1
{
strings:
	$a0 = { b820970010e8e6feffffb834970010e8dcfeffffb848970010e8d2feffffb85c970010e8c8feffffb86c970010e8befeffffb87c970010e8b4feffffb890970010e8aafeffffb8a8970010e8a0feffff }


condition:
	$a0
}