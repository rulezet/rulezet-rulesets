rule Win_Trojan_Proxy_74
{
strings:
	$a0 = { 54f47c00eb02010d5271007100eb005a8b15383e410068d8100d1e81c75928c435bf4efcac12bfaf528d947b0033f9eb0079 }


condition:
	$a0
}