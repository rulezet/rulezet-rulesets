rule Win_Trojan_Vgen_149
{
strings:
	$a0 = { ca2e89165002b430cd218b2e02008b1e2c008edaa38d0a8c068b0a891e870a892e9f0ac706910affff8ec333c0b9ff }


condition:
	$a0
}