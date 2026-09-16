rule Win_Trojan_Vgen_28
{
strings:
	$a0 = { c08ed8803e4c7d0f7213be4d7dacb40e33dbcd100ac075f5c6064c7d00cd1248a31304b106d3e08ec0fcb9000133ff }


condition:
	$a0
}