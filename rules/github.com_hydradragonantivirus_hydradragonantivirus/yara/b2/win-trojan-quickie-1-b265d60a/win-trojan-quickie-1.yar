rule Win_Trojan_Quickie_1
{
strings:
	$a0 = { 15000714812e170013058a260c00be60008bfeb9e603e8d5ffbe4b048bfeb90501e8caff8106 }


condition:
	$a0
}