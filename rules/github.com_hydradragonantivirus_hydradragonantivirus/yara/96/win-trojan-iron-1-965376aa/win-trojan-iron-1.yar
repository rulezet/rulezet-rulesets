rule Win_Trojan_Iron_1
{
strings:
	$a0 = { bc718bc805bc0050b43fcd2158803ebc71b474d05033c933d2b80042cd2159ba0071b440cd21ba }


condition:
	$a0
}