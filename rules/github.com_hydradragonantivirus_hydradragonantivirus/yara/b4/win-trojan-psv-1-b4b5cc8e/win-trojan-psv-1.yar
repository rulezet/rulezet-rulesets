rule Win_Trojan_PSV_1
{
strings:
	$a0 = { b440cd2150558becc74602dc005d50558becc74602 }


condition:
	$a0
}