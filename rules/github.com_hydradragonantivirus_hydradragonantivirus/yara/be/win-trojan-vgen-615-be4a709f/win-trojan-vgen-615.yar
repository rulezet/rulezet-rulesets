rule Win_Trojan_VGEN_615
{
strings:
	$a0 = { 8ed88cc83b0682001f720ab8f600cd283d6f00750d2e803e04014e7403e89503ebb5ba0f04b104d3ea83c220c6 }


condition:
	$a0
}