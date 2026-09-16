rule Win_Trojan_Markiz_1
{
strings:
	$a0 = { f9423161636b4340f9dbb2b1b0558bec5053e800005b81ebeb032e80bf5c0601741b8b46043d }


condition:
	$a0
}