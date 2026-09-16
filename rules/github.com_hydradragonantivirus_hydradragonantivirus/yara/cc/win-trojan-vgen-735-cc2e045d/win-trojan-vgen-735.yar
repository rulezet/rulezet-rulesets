rule Win_Trojan_VGEN_735
{
strings:
	$a0 = { bc0201e800008b2e0001bcfeff81ed0a01b8050333dbcd16e81600eb260000e80f00b440b97d018d960401cd }


condition:
	$a0
}