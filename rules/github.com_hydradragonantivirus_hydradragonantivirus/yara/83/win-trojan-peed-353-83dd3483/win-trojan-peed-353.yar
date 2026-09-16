rule Win_Trojan_Peed_353
{
strings:
	$a0 = { 9bdbe385ff741f81ff0df000007f17b959c940ff4881c1ff45bf00ba02020020 }


condition:
	$a0
}