rule Win_Trojan_Banker_6395
{
strings:
	$a0 = { 53616e205468756e646572204a7572697370727564656e636961 }


condition:
	$a0
}