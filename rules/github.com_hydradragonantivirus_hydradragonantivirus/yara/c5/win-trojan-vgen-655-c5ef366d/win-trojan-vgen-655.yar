rule Win_Trojan_VGEN_655
{
strings:
	$a0 = { 800002770ab409bada01cd21e98800bf6602be8200b98000fcac3c2e7509c704434fc744024d0d3c0d7403aae2eb }


condition:
	$a0
}