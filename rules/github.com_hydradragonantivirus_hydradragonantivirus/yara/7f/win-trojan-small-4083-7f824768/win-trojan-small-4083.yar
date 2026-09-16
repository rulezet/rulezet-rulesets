rule Win_Trojan_Small_4083
{
strings:
	$a0 = { e803000000b8eb5cff0424c381c5??0000 }


condition:
	$a0
}