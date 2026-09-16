rule Win_Trojan_Tiny_9
{
strings:
	$a0 = { a400cc2bc8752ab8024299cca31d02b440803c4d750a395406751638641874118bd6b1a460ccb8 }


condition:
	$a0
}