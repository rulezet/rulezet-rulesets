rule Win_Trojan_Tiny_54
{
strings:
	$a0 = { 0eb601010ebd018006bd0101ba9e00b8013dcd218bd8b80057cd215152b440b9be00ba0001cd21 }


condition:
	$a0
}