rule Win_Trojan_Hupigon_697
{
strings:
	$a0 = { 82d3b538a3c0be406126ae677dc10f9a96ad3ef0e1e9825d31f6a9fe34d58a8858dd3565d8d5510ee72d0ba68aadd3699f1fe0044a5219b04d6e9223 }


condition:
	$a0
}