rule Win_Trojan_Bancos_1726
{
strings:
	$a0 = { 3cc0f676804a72ceeeb43ded648e8b06c51dd2f160f3b81adea445cfb2cdb7ae9fe295b13b2987cb470bd47e64ebc4281d7692d40189ea4e1c7eb88ebb2dc4604ebc8f28ec1b }


condition:
	$a0
}