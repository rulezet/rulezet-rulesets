rule Win_Trojan_Jerkin_6
{
strings:
	$a0 = { b80000cd1a8996bc01b41a8d96be01cd21bf00018db66d00a5a5a5e84100b8000150c32a2e633f6d }


condition:
	$a0
}