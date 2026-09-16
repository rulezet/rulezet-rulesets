rule Win_Trojan_Crazy2_1
{
strings:
	$a0 = { fc52509a0d00ab0059594783ff327ed41eb89400509a0800a80059594683fe327f03e97cff }


condition:
	$a0
}