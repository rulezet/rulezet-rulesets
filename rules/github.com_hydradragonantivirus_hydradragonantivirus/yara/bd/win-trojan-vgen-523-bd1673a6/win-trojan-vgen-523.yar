rule Win_Trojan_VGEN_523
{
strings:
	$a0 = { e859017403e945ffb9181de93cff505581cd0008b0f8e843017509b8f9f5aae8090086c4aa }


condition:
	$a0
}