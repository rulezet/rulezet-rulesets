rule Win_Trojan_Yakes_13
{
strings:
	$a0 = { 52ff1500b040005a81ea9012907c7507eb01500be475fb52bbedcc790d81ebfdc8790d8bd481ea300e000033c9 }


condition:
	$a0
}