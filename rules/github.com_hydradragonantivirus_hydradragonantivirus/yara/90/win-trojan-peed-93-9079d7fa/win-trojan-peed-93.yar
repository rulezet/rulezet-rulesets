rule Win_Trojan_Peed_93
{
strings:
	$a0 = { 8d0d49d73f0081c1d4390000ffd18d0db41d400081c186f7ffffff }


condition:
	$a0
}