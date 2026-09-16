rule Win_Trojan_Ti_1
{
strings:
	$a0 = { 0e1f07e800005d81ed0c0160e84500b44ecd2161071f2e80be1702017411bf00018db65201a5a42bff8bef6800 }


condition:
	$a0
}