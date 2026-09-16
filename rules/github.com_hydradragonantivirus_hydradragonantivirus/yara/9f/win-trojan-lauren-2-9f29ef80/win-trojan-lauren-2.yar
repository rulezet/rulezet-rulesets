rule Win_Trojan_Lauren_2
{
strings:
	$a0 = { 424156e800005d81ed0a01bf00018db66703fca5a5a5a4b8ffff5058fa83ec }


condition:
	$a0
}