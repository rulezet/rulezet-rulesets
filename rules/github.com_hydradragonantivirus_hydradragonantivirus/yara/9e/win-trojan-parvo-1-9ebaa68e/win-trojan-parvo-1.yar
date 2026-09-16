rule Win_Trojan_Parvo_1
{
strings:
	$a0 = { 5b5f535e664be820ffffff0f8d030000006687fe87eb6681f30acf66438bf94b81ff219e384c0f8486c7ffff8bf7e938ffffff }


condition:
	$a0
}