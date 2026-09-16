rule Win_Trojan_IVP_4
{
strings:
	$a0 = { 35cd212e891ecb012e8c06cd01b425ba9601cd210e07bac501e81300b409ba9901cd21b82425bacb01cd210e1fcd }


condition:
	$a0
}