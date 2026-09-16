rule Win_Trojan_Bancos_1783
{
strings:
	$a0 = { ab8b8ad78643d80128734f2a13dd85fe7e3f95c5654bf160c69cedc9f4d907f1d322f5f4a79031d6e0027049b0044de61de6d8a3df9427fa4fc17aa5847fead4154145ff5303 }


condition:
	$a0
}