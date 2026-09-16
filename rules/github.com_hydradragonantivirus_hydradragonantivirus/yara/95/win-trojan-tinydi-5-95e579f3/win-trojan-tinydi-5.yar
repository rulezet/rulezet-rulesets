rule Win_Trojan_TinyDI_5
{
strings:
	$a0 = { 3dcd218bd8061f8bd733c949b43fcd21056e005041b8 }


condition:
	$a0
}