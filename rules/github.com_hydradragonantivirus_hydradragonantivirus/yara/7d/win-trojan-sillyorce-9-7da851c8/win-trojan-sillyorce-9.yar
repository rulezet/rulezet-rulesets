rule Win_Trojan_SillyORCE_9
{
strings:
	$a0 = { cd21bf2001891d8c4502b82125ba1a01cd21ba4701cd2780fc3d7405ea }


condition:
	$a0
}