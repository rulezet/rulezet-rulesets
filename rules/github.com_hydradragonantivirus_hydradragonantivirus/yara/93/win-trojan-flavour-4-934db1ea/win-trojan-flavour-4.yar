rule Win_Trojan_Flavour_4
{
strings:
	$a0 = { 8becfabc00008be5fbe800005e81ee????b42acd2181fa0909750bb4098d94????cd21faebfdb8008fcd213d8f00750f81c61e01bf00011657fca5a5161fcb }


condition:
	$a0
}