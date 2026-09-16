rule Win_Trojan_Small_4101
{
strings:
	$a0 = { e81e000000c9e829000000c23000bd0b????ffeb1255555f }


condition:
	$a0
}