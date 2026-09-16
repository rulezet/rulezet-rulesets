rule Win_Trojan_Proxy_92
{
strings:
	$a0 = { 60b904000000c1e80523d3e811000000bb880000000bcbc1e208b863 }


condition:
	$a0
}