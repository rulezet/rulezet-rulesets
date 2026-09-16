rule Win_Trojan_Hbr_1
{
strings:
	$a0 = { 9e00cd2193b80242b440b98700ba0001cd21b43ecd21b44febd8b409ba5c01cd21b40dcd21b002 }


condition:
	$a0
}