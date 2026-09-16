rule Win_Trojan_Beech_1
{
strings:
	$a0 = { b9b701b440e8da0039c8750ee84800bab401b90300b440e8c800b801578b0eba018b16bc01e8 }


condition:
	$a0
}