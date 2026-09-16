rule Win_Trojan_Vindicator_2
{
strings:
	$a0 = { b80010f6e70500b88ed831f6b82000baa08031db38e372 }


condition:
	$a0
}