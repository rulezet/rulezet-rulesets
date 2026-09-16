rule Win_Trojan_Search_13
{
strings:
	$a0 = { 03008bf581c6fa018944018bf58bfe81c6c40181c7fd01 }


condition:
	$a0
}