rule Win_Trojan_Downloader_162
{
strings:
	$a0 = { 77696e646f772e6576616c2829[0-30]6666663d6f702e73706c69742822363622 }


condition:
	$a0
}