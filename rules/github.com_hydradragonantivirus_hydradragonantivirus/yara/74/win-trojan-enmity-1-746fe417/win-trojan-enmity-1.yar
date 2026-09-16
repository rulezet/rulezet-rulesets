rule Win_Trojan_Enmity_1
{
strings:
	$a0 = { 558becc74602011a5d50558becc7460200015d8db623045fa5a5a48d9695045848cd21b44732d2 }


condition:
	$a0
}