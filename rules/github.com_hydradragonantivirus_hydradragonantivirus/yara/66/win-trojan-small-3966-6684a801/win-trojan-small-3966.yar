rule Win_Trojan_Small_3966
{
strings:
	$a0 = { bfcbacbff881c73565890789fe8d9fd01afe0481eb5416fe0453ff15f81649000500e023bf290731c08d7f0183c7024739df7ee5ffe6 }


condition:
	$a0
}