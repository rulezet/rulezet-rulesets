rule Win_Trojan_Small_153
{
strings:
	$a0 = { 015760fcbeff0003750166a533c98ec1bf0403b19926803dbf7414f3a48ed966a1840066a38603b82125ba3d03cd }


condition:
	$a0
}