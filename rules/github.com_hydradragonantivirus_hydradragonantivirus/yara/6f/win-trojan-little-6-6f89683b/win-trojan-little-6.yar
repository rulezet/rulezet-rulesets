rule Win_Trojan_Little_6
{
strings:
	$a0 = { b440ba00018b0d81c18b00cd21b43ecd218cd08ed88ec050d1eab41acd21bf0001 }


condition:
	$a0
}