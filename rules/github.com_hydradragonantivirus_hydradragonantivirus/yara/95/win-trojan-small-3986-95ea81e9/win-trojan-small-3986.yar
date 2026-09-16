rule Win_Trojan_Small_3986
{
strings:
	$a0 = { e82d00000009c0742889c281c2fe7140008d8a7cf400ff8d890010ff005231c005ffdfad }


condition:
	$a0
}