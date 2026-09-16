rule Win_Trojan_Birgit_2
{
strings:
	$a0 = { f3a43e80868a03015b53b440b902008d968a03cd215b53b440b904008d969303cd215b53 }


condition:
	$a0
}