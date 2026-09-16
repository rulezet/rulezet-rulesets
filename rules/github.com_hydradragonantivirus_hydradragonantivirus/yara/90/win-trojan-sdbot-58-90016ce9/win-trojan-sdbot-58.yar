rule Win_Trojan_SdBot_58
{
strings:
	$a0 = { f2d5cf2a4e4a3d8b77079455bf52626f77e2357ca7b0ab96ca5295bc91876e5368ec0b571c7e8ed01254575c }


condition:
	$a0
}