rule Win_Trojan_Obfuscator_1
{
strings:
	$a0 = { 543a5c446576656c6f7020576f726b5c5370616365315c }


condition:
	$a0
}