rule Win_Trojan_Tumen_1
{
strings:
	$a0 = { 2180fcff742c8b078a4f02a30001880e02015d5f5e }


condition:
	$a0
}