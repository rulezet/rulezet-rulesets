rule Win_Trojan_W_22
{
strings:
	$a0 = { cd210e078b5ef8b98000518ad1b9ff00518ae9b80203 }


condition:
	$a0
}