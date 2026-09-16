rule Win_Trojan_Alla_2
{
strings:
	$a0 = { 6e0083ed03e860002ec6867f0500b8bebecd130bc0745490909033ff8cd8488ed8803d5a7545909090c6054d83 }


condition:
	$a0
}